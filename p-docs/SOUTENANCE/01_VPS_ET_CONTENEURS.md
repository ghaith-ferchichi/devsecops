# 01 — Le VPS et les conteneurs

> Document de référence pour la soutenance technique.
> Objectif : pouvoir expliquer **chaque conteneur**, **son rôle**, **ses ports**, et **comment il communique** avec les autres, sans hésiter devant l'écran partagé.

---

## 1. Le serveur (VPS)

| Élément | Valeur |
|---|---|
| Hébergeur | VPS dédié (OVH), IP publique `141.94.92.226` |
| CPU | Intel Haswell, **12 vCPU** (inférence **CPU-only**, pas de GPU) |
| RAM | **45 Gio** |
| OS | Linux (Ubuntu Server) |
| Orchestration | **Docker Compose** (un seul fichier `docker-compose.yml`) |
| Réseau interne | bridge Docker `devsecops-net`, sous-réseau `172.20.0.0/16` |

**Point clé à dire** : tout tourne **CPU-only**. C'est la contrainte centrale du projet — elle explique le choix des modèles quantifiés (qwen2.5-coder 7B / 14B), le tuning d'Ollama (Flash Attention, KV-cache q8_0, pin sur 12 threads), et le fait que le pipeline dure 15 à 25 min au lieu de quelques secondes sur GPU.

---

## 2. Vue d'ensemble : 11 conteneurs cœur (+ 1 sandbox optionnelle)

Le `docker-compose.yml` déclare **11 services** cœur, organisés en 4 couches. Un **12ᵉ** conteneur, `localai`, peut tourner en plus : c'est une **sandbox optionnelle** (fichier `docker-compose.localai.yml`) servant de second backend d'inférence pour le benchmark A/B (Post-Sprint 8).

> ⚠️ **À savoir avant la démo** : `docker compose ps` affiche actuellement **12 conteneurs** (les 11 + `localai`). Si la reviewer le remarque, l'expliquer simplement : « `localai` est une sandbox d'évaluation que j'ai ajoutée pour comparer un second moteur d'inférence à Ollama ; elle est optionnelle et non critique — d'où ses alertes en sévérité `info`. Le système cœur, ce sont les 11 autres. »

```
┌──────────────────────── COUCHE EXPOSITION ────────────────────────┐
│  nginx  (reverse proxy + HTTP Basic Auth, unique point d'entrée)   │
└────────────────────────────────────────────────────────────────────┘
            │
┌──────────────────────── COUCHE APPLICATIVE ───────────────────────┐
│  agent (FastAPI + LangGraph)      open-webui (UI de test Ollama)   │
│  ollama (serveur d'inférence LLM)                                  │
└────────────────────────────────────────────────────────────────────┘
            │
┌──────────────────────── COUCHE DONNÉES ───────────────────────────┐
│  postgres (mémoire long terme + checkpoints)   redis (cache rapide)│
└────────────────────────────────────────────────────────────────────┘
            │
┌──────────────────────── COUCHE OBSERVABILITÉ ─────────────────────┐
│  prometheus   victoriametrics   grafana   alertmanager             │
│  node-exporter (métriques de l'hôte)                               │
└────────────────────────────────────────────────────────────────────┘
```

---

## 3. Fiche détaillée de chaque conteneur

### 3.1 `nginx` — reverse proxy (point d'entrée unique)
- **Image** : `nginx:alpine`
- **Ports** : `80`, `443` (les seuls réellement exposés au public)
- **Rôle** : unique porte d'entrée. Route le trafic vers les conteneurs internes et **protège** l'UI et l'API de chat par **HTTP Basic Auth** (`/etc/nginx/.htpasswd`).
- **Routes** :
  - `/` → redirige (301) vers `/ui` (l'interface de chat)
  - `/ui` et `/chat/` → `agent:8000` (protégé par Basic Auth ; SSE : `proxy_buffering off`, HTTP/1.1, timeout 1800 s pour le cold-load des gros modèles)
  - `/grafana/` → `grafana:3000`
  - `/prometheus/`, `/alertmanager/` → conteneurs correspondants
- **À dire** : « Rien n'est joignable directement de l'extérieur sauf à travers nginx. C'est lui qui porte l'authentification et qui isole la stack interne. »

### 3.2 `agent` — le cœur du système (FastAPI + LangGraph)
- **Build** : `./agent/Dockerfile` (Python 3.11)
- **Conteneur** : `devsecops-agent`, port interne `8000`
- **Rôle** : le cerveau. Reçoit les webhooks GitHub, orchestre le pipeline de revue (LangGraph), lance les 5 scanners, appelle les LLM via Ollama, publie les revues sur GitHub, expose le chat ops et les métriques.
- **Montages importants** :
  - `/var/run/docker.sock` → permet à l'agent de **builder des images** et **lancer les scanners** dans des conteneurs éphémères, et de lire les `docker stats`.
  - `./artifacts` → stockage disque des résultats de scan (JSON brut par scanner / PR).
- **Dépend de** : `ollama`, `postgres`, `redis` (démarrage conditionné à leur `healthcheck`).
- **Détail du code** : voir `02_CODE_AGENT.md`.

### 3.3 `ollama` — serveur d'inférence LLM
- **Image** : `ollama/ollama:latest`, port interne `11434`
- **Rôle** : sert les modèles **qwen2.5-coder** (`7b` pour la classification et le chat, `14b` pour la revue combinée).
- **Tuning CPU-only** (variables d'env — à connaître, elle peut demander) :
  - `OLLAMA_FLASH_ATTENTION=1` → complexité mémoire O(n²)→O(n), critique pour un contexte de 16K.
  - `OLLAMA_KV_CACHE_TYPE=q8_0` → cache KV quantifié 8 bits, ~650 Mo économisés à 16K.
  - `OLLAMA_NUM_THREAD=12` → épingle les 12 cœurs Haswell.
  - `OLLAMA_NUM_PARALLEL=1` + `OLLAMA_MAX_LOADED_MODELS=1` → une seule inférence à la fois, tous les cœurs dédiés.
  - `OLLAMA_KEEP_ALIVE=20m` → garde le modèle « chaud » 20 min pour éviter les rechargements.
  - Limite mémoire : `42g` (14B ≈ 11 Go + KV 16K ≈ 1,3 Go + marge OS).

### 3.4 `postgres` — mémoire long terme
- **Image** : `postgres:16-alpine`, port interne `5432`
- **Base** : `devsecops_db`, user `devsecops`
- **Double rôle** :
  1. **Knowledge base** (service `knowledge.py`) : historique des revues, profils de dépôts, résultats de scan.
  2. **Checkpointer LangGraph** (`langgraph-checkpoint-postgres`) : persiste l'état du graphe → permet de **reprendre** un workflow interrompu (ex. après l'approbation Slack).
- **Tables** (script `db/init.sql`) : `pr_reviews`, `scan_results`, `repo_profiles`, `sbom_cache`, `security_policies`, `incidents`.
- **À dire** : « Postgres sert deux choses : la mémoire métier de l'agent, et la persistance technique du graphe LangGraph. »

### 3.5 `redis` — cache rapide
- **Image** : `redis:7-alpine`, port interne `6379`
- **Config** : `maxmemory 256mb`, politique `allkeys-lru`, `appendonly yes`.
- **Trois usages** (service `cache.py`) :
  1. **Déduplication** des webhooks : clé posée avec `NX` + TTL 1 h → on ne re-traite pas deux fois la même PR.
  2. **Rate limiting** : max **3 PR concurrentes** par dépôt (fenêtre 10 min) → protège le CPU.
  3. **Cache des scans** : résultats sérialisés en JSON, TTL 1 h.
- **À dire** : « Redis, c'est la mémoire courte / le garde-fou. Postgres, c'est la mémoire longue. »

### 3.6 `node-exporter` — métriques de l'hôte
- **Image** : `prom/node-exporter:latest`
- **Spécificité** : tourne en **`pid: host` + `network_mode: host`** → c'est le **seul** conteneur hors du réseau bridge. Indispensable pour voir les **vrais** processus, interfaces et systèmes de fichiers de l'hôte, pas ceux du conteneur.
- **Monte** `/proc`, `/sys`, `/` en lecture seule.
- **Scrappé par Prometheus** via la gateway du bridge `172.20.0.1:9100` (parce qu'il est en host network).
- **À dire** : « Pour mesurer la machine hôte — CPU, RAM, disque réels — il faut sortir du namespace Docker. D'où `pid:host` et `network_mode:host`. »

### 3.7 `prometheus` — collecte de métriques + règles d'alerte
- **Image** : `prom/prometheus:latest`, port interne `9090`
- **Rôle** : scrape les métriques toutes les **15 s**, évalue **15 règles d'alerte**, pousse les alertes vers AlertManager.
- **Cibles scrappées** : `devsecops-agent:8000/metrics`, `node-exporter` (172.20.0.1:9100), lui-même, `alertmanager`.
- **`remote_write`** → `victoriametrics:8428` (stockage long terme).
- **Rétention locale** : 30 jours.

### 3.8 `victoriametrics` — stockage long terme des métriques
- **Image** : `victoriametrics/victoria-metrics:latest`, port interne `8428`
- **Rôle** : TSDB compatible Prometheus, **rétention 90 jours**. Prometheus lui envoie tout en `remote_write`.
- **À dire** : « Prometheus garde 30 jours en local pour le temps réel ; VictoriaMetrics conserve 90 jours pour l'historique long terme, plus efficace en stockage. Les deux sont des datasources dans Grafana. »

### 3.9 `alertmanager` — routage des alertes
- **Image** : `prom/alertmanager:latest`, port interne `9093`
- **Rôle** : reçoit les alertes de Prometheus, les déduplique/groupe, et les route :
  - vers **Slack** (notification humaine),
  - vers l'**agent** (`POST /webhooks/alertmanager`) pour **auto-remédiation** : sur `DiskCritical`/`AgentDiskCritical`, l'agent lance `docker builder prune -f`.
- **À dire** : « C'est la boucle autonome : Prometheus détecte → AlertManager route → l'agent agit tout seul sur le disque. »

### 3.10 `grafana` — visualisation
- **Image** : `grafana/grafana:latest`, port interne `3000`
- **Datasources provisionnées** : **Prometheus** (défaut), **VictoriaMetrics**, **PostgreSQL**.
- **Dashboards** : 3 tableaux de bord opérationnels (santé de l'agent, hôte/conteneurs, pipeline de revue).
- **Accès** : via `/grafana/` derrière nginx.

### 3.11 `open-webui` — UI de test d'Ollama
- **Image** : `ghcr.io/open-webui/open-webui:main`, port interne `8080`
- **Rôle** : interface web pour **tester manuellement** les modèles Ollama (utile en démo pour montrer un prompt direct au LLM). Branchée sur `ollama:11434`.

### (12) `localai` — sandbox d'inférence optionnelle
- **Compose** : `docker-compose.localai.yml` (séparé du cœur), port interne `8080`
- **Rôle** : **second backend d'inférence** pour un benchmark A/B contre Ollama (Post-Sprint 8). Le routeur de chat de l'agent peut cibler `ollama/...` ou `localai/...`. Conclusion du benchmark : Ollama ~+22 % de débit sur modèle identique → Ollama reste le backend de production, LocalAI reste une sandbox.
- **Non critique** : ses alertes Prometheus sont en sévérité `info`. Apparaît dans `docker compose ps` mais ne fait pas partie des 11 conteneurs cœur.

---

## 4. Communication entre les conteneurs (le schéma à savoir par cœur)

### Flux 1 — Revue d'une Pull Request (le flux principal)
```
GitHub ──webhook (HMAC-SHA256)──▶ nginx:443 ──▶ agent:8000  /webhooks/github
   agent ──git clone / diff -U15──▶ (dépôt cloné dans le workspace)
   agent ──docker.sock──▶ build image + lance les 5 scanners (conteneurs éphémères)
   agent ──HTTP──▶ ollama:11434   (classify 7B, puis revue combinée 14B)
   agent ──SQL──▶ postgres:5432   (sauvegarde revue + historique)
   agent ──GET/SET──▶ redis:6379  (dédup, rate-limit, cache scans)
   agent ──API REST──▶ GitHub     (poste la revue + commentaires inline + commit status)
   agent ──(si CRITICAL/HIGH)──▶ Slack  (demande d'approbation, le graphe se met en pause)
```

### Flux 2 — Observabilité
```
prometheus ──scrape /metrics (15s)──▶ agent:8000, node-exporter:9100, alertmanager
prometheus ──remote_write──▶ victoriametrics:8428         (rétention 90j)
prometheus ──évalue 15 règles──▶ alertmanager:9093
alertmanager ──▶ Slack (humain)  +  ──▶ agent /webhooks/alertmanager (auto-remédiation disque)
grafana ──query──▶ prometheus / victoriametrics / postgres
```

### Flux 3 — Chat Ops (assistant ReAct)
```
Navigateur ──Basic Auth──▶ nginx /chat/ ──SSE──▶ agent:8000 /chat/stream
   agent (boucle ReAct, max 8 outils) ──▶ ollama:11434  (qwen2.5-coder:7b)
   les 19 outils interrogent : docker.sock, prometheus, redis, postgres, artifacts…
```

**Phrase de synthèse** : « Tout passe par le réseau bridge interne `devsecops-net`. L'agent est au centre : il parle à Ollama pour l'IA, à Postgres et Redis pour la mémoire, à Docker pour les scanners, et à GitHub/Slack vers l'extérieur. Prometheus observe tout le monde, VictoriaMetrics archive, Grafana affiche, AlertManager réagit. »
