# Recap — BTE Security AI Agent
## Guide de préparation à la soutenance encadrant

> Document de référence pour la présentation à l'encadrant. Couvre l'intégralité
> du système déployé sur le VPS : les 13 conteneurs, leur rôle individuel,
> les flux de communication, et le fonctionnement détaillé de l'agent.
>
> Lis-le dans l'ordre — chaque section s'appuie sur les précédentes.

---

## 0. Le projet en une page

Le **BTE Security AI Agent** est une plateforme DevSecOps autonome déployée sur un VPS pour la Banque de Tunisie et des Emirats. Elle automatise la revue de sécurité des *Pull Requests* GitHub en moins de sept minutes, sans envoyer le moindre octet de code à un service tiers — toute l'intelligence (deux modèles de langage Qwen2.5-Coder) tourne en local.

Concrètement, quand un développeur ouvre une PR sur l'un des dépôts surveillés, GitHub déclenche un webhook signé HMAC-SHA256 vers le VPS. L'agent classifie la PR avec un petit modèle 7B, fait tourner cinq scanners de sécurité en parallèle (Trivy, Gitleaks, Semgrep, Checkov, OSV), puis demande à un modèle 14B de synthétiser tout cela en un commentaire de revue déposé directement sur la PR — avec un score de risque, un verdict (APPROVE / REQUEST_CHANGES / BLOCK), et des suggestions de correction *inline* sur les lignes problématiques.

Autour de ce pipeline central, treize conteneurs Docker se coordonnent pour assurer le stockage (PostgreSQL + Redis), l'inférence (Ollama + LocalAI), l'exposition (Nginx + Open WebUI), l'observabilité (Prometheus + AlertManager + Grafana + VictoriaMetrics + node-exporter), l'intégration continue (Jenkins) et l'autonomie opérationnelle (scheduler interne à l'agent).

**Chiffres clés à retenir :**

| Indicateur | Valeur |
|---|---|
| Conteneurs déployés | 13 (12 production + 1 sandbox LocalAI) |
| Durée d'une revue PR (bout en bout) | 6–11 minutes |
| Scanners de sécurité enchaînés | 5 (Trivy, Gitleaks, Semgrep, Checkov, OSV) |
| Modèles LLM | 2 (qwen2.5-coder 7B + 14B, exécutés via Ollama) |
| Métriques Prometheus exposées | 28 (custom) + métriques HTTP automatiques |
| Alertes configurées | 12 règles dans `prometheus/alerts.rules.yml` |
| Outils ops disponibles dans le chat | 20 |
| Sprints du projet | 8 sur 4 mois, méthodologie Scrumban (WIP=1) |

---

## 1. Vue d'ensemble du VPS

### 1.1 Caractéristiques matérielles

| Ressource | Valeur |
|---|---|
| CPU | 12 cœurs Haswell (AVX2, pas d'AVX-512, pas de GPU) |
| RAM | 45 Go (≈ 15 Go utilisés, ≈ 30 Go disponibles) |
| Disque | 290 Go (≈ 124 Go utilisés, ≈ 167 Go libres — 43 %) |
| OS | Ubuntu Linux (kernel 6.14) |
| Uptime au moment de la rédaction | 42 jours |
| Docker | Engine + containerd snapshotter |

**Pourquoi ces choix matériels comptent.** Le CPU est en architecture Haswell, donc Ollama charge automatiquement la bibliothèque optimisée `libggml-cpu-haswell.so`. L'absence de GPU pousse le projet à privilégier des modèles de 7 à 14 milliards de paramètres en quantification Q4_K_M — un modèle 32B serait trois à quatre fois plus lent sans bénéfice qualitatif suffisant. Les 45 Go de RAM permettent de garder en mémoire un modèle 14B (9 Go) avec tout le contexte (KV cache, ≈ 1,3 Go à 16K tokens) et la pile de conteneurs (≈ 5 Go cumulés), tout en laissant de la marge pour Linux et le cache page.

### 1.2 Snapshot à l'instant T

À l'instant de la rédaction de ce document : **13 conteneurs en cours d'exécution**, tous opérationnels, dont 9 marqués `healthy` par leurs *healthchecks* Docker, et 4 sans healthcheck défini (jenkins, nginx, node-exporter, grafana — leurs problèmes seraient remontés par Prometheus).

```
NAME             IMAGE                                    STATUS                  PORTS
localai          localai/localai:latest-cpu               Up 30 hours (healthy)   8081→8080
devsecops-agent  devsecops-agent                          Up 31 hours (healthy)   8000→8000
nginx            nginx:alpine                             Up 2 weeks              80→80, 443→443
node-exporter    prom/node-exporter:latest                Up 2 weeks              (host network)
grafana          grafana/grafana:latest                   Up 31 hours             3000→3000
ollama           ollama/ollama:latest                     Up 3 weeks (healthy)    11434 (interne)
open-webui       ghcr.io/open-webui/open-webui:main       Up 3 weeks (healthy)    3001→8080
prometheus       prom/prometheus:latest                   Up 31 hours             9090→9090
alertmanager     prom/alertmanager:latest                 Up 3 weeks              9093→9093
victoriametrics  victoriametrics/victoria-metrics:latest  Up 2 weeks              8428→8428
jenkins          devsecops-jenkins                        Up 4 weeks              8080→8080
redis            redis:7-alpine                           Up 5 weeks (healthy)    6379→6379
postgres         postgres:16-alpine                       Up 5 weeks (healthy)    5432 (interne)
```

Modèles LLM disponibles sur Ollama :

| Modèle | Taille disque | Rôle |
|---|---|---|
| `qwen2.5-coder:7b` | 4,7 Go | Classification rapide (PR feature / dependency / IaC / docs / config) |
| `qwen2.5-coder:14b` | 9,0 Go | Revue de sécurité complète + suggestions de code |
| `llama3.2:3b` | 2,0 Go | Réserve pour expérimentations |
| `granite3.1-dense:2b` | 1,6 Go | Réserve pour expérimentations |

---

## 2. Diagramme d'architecture global

```
                              EXTÉRIEUR (Internet)
                                       │
                  ┌────────────────────┼────────────────────┐
                  │                    │                    │
            GitHub webhook       Navigateur                Slack
            (PR opened)        (Chat UI / Grafana)       (callbacks)
                  │                    │                    │
                  ▼                    ▼                    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                    Nginx (alpine) — port 80                  │
   │   reverse proxy + auth basic + résolveur Docker (127.0.0.11) │
   └──────┬──────────┬──────────┬──────────┬──────────┬──────────┘
          │          │          │          │          │
          ▼          ▼          ▼          ▼          ▼
       /ui      /chat/    /webhooks/  /api/      /grafana/
       /api     (SSE)     github     /callbacks  /prometheus/
                                     /slack      /jenkins/
          │          │          │          │
          └──────────┴──────────┴──────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │   devsecops-agent (FastAPI :8000)   │
        │   ─ webhooks router                 │
        │   ─ callbacks router                │
        │   ─ health router (+ /metrics)      │
        │   ─ chat router (SSE + ReAct)       │
        │   ─ LangGraph workflows (7)         │
        │   ─ scheduler asyncio (disk + Slack)│
        │   ─ pollers (Ollama / LocalAI / Docker)│
        └────┬─────────┬───────────┬──────────┘
             │         │           │
   ┌─────────▼──┐  ┌───▼────┐  ┌───▼──────────┐
   │ Ollama    │  │ Redis  │  │ PostgreSQL   │
   │ :11434    │  │ :6379  │  │ :5432        │
   │ (LLMs 7B  │  │ (cache │  │ (checkpoints │
   │  + 14B)   │  │  dedup │  │  + knowledge │
   │           │  │  rate) │  │  base)       │
   └───────────┘  └────────┘  └──────────────┘
             │                       │
             │                       │ (lecture par Grafana datasource)
             ▼                       │
   ┌──────────────────┐              │
   │ LocalAI :8080    │              │
   │ (sandbox A/B)    │              │
   └──────────────────┘              │
                                     │
                                     ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                      Observabilité                          │
   │                                                             │
   │   node-exporter ──► Prometheus ──remote_write──► VictoriaMetrics
   │   (host)            :9090         (rétention 90j)  :8428    │
   │                       │                                     │
   │                       │ rule_files: 12 alertes              │
   │                       ▼                                     │
   │                   AlertManager :9093                        │
   │                       │                                     │
   │                       │ webhook                             │
   │                       ▼                                     │
   │                   /webhooks/alertmanager                    │
   │                       │                                     │
   │                       ▼                                     │
   │                   Slack #security-channel                   │
   │                                                             │
   │   Prometheus + VictoriaMetrics ──► Grafana :3000            │
   │                                    (3 dashboards)           │
   └─────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────┐
   │                     Outils annexes                          │
   │                                                             │
   │   Jenkins :8080  ─ CI/CD (build images Docker, tests)       │
   │   Open WebUI :3001 ─ interface graphique pour Ollama        │
   └─────────────────────────────────────────────────────────────┘

   Volumes persistants :
   ./artifacts/        ─ outputs SAST + logs JSON
   postgres_data       ─ knowledge base
   redis_data          ─ cache (AOF activé)
   ollama_data         ─ modèles GGUF téléchargés
   prometheus_data     ─ TSDB local 30 jours
   victoriametrics_data ─ TSDB long terme 90 jours
   grafana_data        ─ dashboards + configuration
   jenkins_data        ─ pipelines + secrets
```

**Réseau Docker.** Tous les conteneurs sauf `node-exporter` (qui tourne en *host network mode* pour voir les vraies métriques du noyau) sont sur un même réseau bridge nommé `devsecops_devsecops-net`, sous-réseau `172.20.0.0/16`. La résolution DNS interne de Docker permet à chaque conteneur de joindre les autres par leur nom (`postgres`, `redis`, `ollama`, etc.) sans avoir à connaître leur IP.

---

## 3. Cartographie détaillée des conteneurs

Cette section décrit chaque conteneur : à quoi il sert, comment il est configuré, et comment il s'intègre dans la chaîne. Mémorise au moins le rôle et un fait distinctif de chacun — c'est ce que l'encadrant te demandera en premier.

### 3.1 `devsecops-agent` — le cerveau

**Image :** construite localement depuis `./agent/Dockerfile` (Python 3.12-slim, ≈ 1,55 Go).
**Port :** 8000 (exposé sur l'hôte).
**Healthcheck :** `GET /health` toutes les 15 s.
**RAM consommée :** ≈ 120 Mo en régime stable.

C'est la pièce centrale. Tout passe par ici : les webhooks GitHub, les requêtes de l'interface chat, les callbacks Slack, les alertes AlertManager, l'orchestration des sept workflows LangGraph, l'exécution des scanners de sécurité (Trivy, Gitleaks, Semgrep, Checkov, OSV — tous installés dans l'image), les appels aux modèles Ollama, et le scheduler autonome qui surveille le disque et envoie le résumé quotidien Slack.

L'agent monte le socket Docker (`/var/run/docker.sock`) en lecture-écriture : c'est ce qui lui permet (1) de construire les images Docker des PR à analyser via `trivy_service`, (2) de récupérer les statistiques par conteneur (CPU, RAM, réseau) toutes les 30 secondes pour les exposer en métriques Prometheus (remplace cAdvisor qui est incompatible avec le snapshotter containerd), (3) d'effectuer un `docker builder prune` automatique quand le scheduler détecte un disque saturé.

Quatre routers FastAPI sont enregistrés :

| Router | Module | Endpoints |
|---|---|---|
| Webhooks | `app.routers.webhooks` | `POST /webhooks/github`, `POST /webhooks/alertmanager` |
| Callbacks | `app.routers.callbacks` | `POST /callbacks/slack` |
| Health | `app.routers.health` | `GET /health`, `GET /metrics` |
| Chat | `app.routers.chat` | `GET /ui`, `GET /chat/models`, `POST /chat/stream` |

Quatre tâches asynchrones tournent en arrière-plan en plus des handlers HTTP :

1. **Poller Ollama** — toutes les 30 s, interroge `/api/ps` pour mettre à jour les jauges Prometheus (`ollama_reachable`, `ollama_model_loaded`, `ollama_models_loaded_total`).
2. **Poller LocalAI** — toutes les 30 s, interroge `/readyz` et `/v1/models` (silencieux si la sandbox n'est pas déployée).
3. **Poller Docker stats** — toutes les 30 s, lit le socket Docker pour exposer `container_cpu_percent`, `container_memory_bytes`, `container_network_*_bytes` par conteneur. Remplace cAdvisor.
4. **Scheduler** — boucle disque toutes les 30 minutes (avec auto-cleanup à > 90 % et alerte Slack à > 80 %) + résumé Slack quotidien à 09:00 UTC.

### 3.2 `ollama` — serveur d'inférence LLM

**Image :** `ollama/ollama:latest`.
**Port :** 11434, **non exposé sur l'hôte** — accessible uniquement depuis le réseau Docker. Garantie qu'aucun code source ne peut quitter l'infrastructure.
**RAM consommée :** ≈ 1,3 Go au repos, ≈ 10 Go quand le modèle 14B est chargé.

Ollama gère la quantification, le mmap et l'inférence pour les modèles `qwen2.5-coder:7b` et `qwen2.5-coder:14b` (les deux autres modèles téléchargés servent d'expérimentation et ne sont pas appelés par le pipeline). Configuration de tuning critique passée en variables d'environnement :

| Variable | Valeur | Rôle |
|---|---|---|
| `OLLAMA_FLASH_ATTENTION` | `1` | Active Flash Attention — passe la mémoire attention de O(n²) à O(n), indispensable pour un contexte de 12 288 tokens. |
| `OLLAMA_KV_CACHE_TYPE` | `q8_0` | Quantifie le KV cache en 8 bits, économise ≈ 650 Mo de RAM à 16K. |
| `OLLAMA_NUM_THREAD` | `12` | Toutes les cœurs Haswell, sélection auto de `libggml-cpu-haswell.so`. |
| `OLLAMA_MAX_LOADED_MODELS` | `1` | Un seul modèle en RAM à la fois — toute la RAM est consacrée au modèle actif. |
| `OLLAMA_NUM_PARALLEL` | `1` | Une seule requête simultanée — les 12 cœurs vont à une seule inférence. |
| `OLLAMA_KEEP_ALIVE` | `20m` | Le modèle reste chaud 20 minutes après la dernière requête. |

Limite mémoire Docker fixée à 42 Go (le 14B occupe ≈ 9 Go + 1,3 Go de KV cache à 12K + overhead OS). `shm_size: 2gb` car la mémoire partagée par défaut (64 Mo) saturait avec les buffers de synchronisation entre threads.

**Modes d'appel depuis l'agent.** L'agent instancie quatre `ChatOllama` *factory functions* mises en cache via `@lru_cache` :

| Fonction | Modèle | `num_ctx` | `num_predict` | `format` | Usage |
|---|---|---|---|---|---|
| `get_fast_llm()` | 7b | 4096 | 512 | `"json"` | `classify_node` |
| `get_combined_llm()` | 14b | 12288 | 2500 | aucun | `analyze_review_node` |
| `get_deep_llm()` | 14b | 8192 | 1500 | aucun | Réserve pour analyse de sécurité seule |
| `get_review_llm()` | 14b | 8192 | 2048 | `"json"` | Réserve pour revue de code seule |

### 3.3 `postgres` — base de connaissances + checkpoints

**Image :** `postgres:16-alpine`.
**Port :** 5432, **non exposé sur l'hôte**.
**RAM consommée :** ≈ 33 Mo.

PostgreSQL joue deux rôles distincts :

1. **Base de connaissances.** Les tables `pr_reviews`, `scan_results`, `repo_profiles` et `security_policies` accumulent les revues passées. Le `repo_history` injecté dans le prompt de `analyze_review_node` est tiré de cette base via `app.services.knowledge.get_repo_history()` — l'agent connaît donc les patterns récurrents de chaque dépôt et peut signaler les régressions.
2. **Checkpoints LangGraph.** Chaque workflow LangGraph utilise un `AsyncPostgresSaver` qui sérialise l'état du graphe après chaque transition de nœud. Si l'agent crashe en plein milieu d'une revue, le pipeline reprend exactement où il s'est arrêté à la prochaine relance. C'est aussi ce qui permet le *Slack approval gate* (le nœud `escalate` est marqué `interrupt_before` — l'état est checkpointé, le humain valide via `POST /callbacks/slack`, et le pipeline reprend).

Le script `db/init.sql` est exécuté à la première création du conteneur pour créer les tables.

### 3.4 `redis` — cache, déduplication, rate limiting

**Image :** `redis:7-alpine`.
**Port :** 6379, **exposé sur l'hôte sans authentification** (point à corriger — listé dans le chapitre 4.6 du PFE).
**RAM consommée :** ≈ 5 Mo.

Configuration : `maxmemory 256mb`, politique `allkeys-lru` (les clés les moins récemment utilisées sont évincées), AOF (`appendonly yes`) pour la persistance.

Trois usages dans le pipeline PR review :

| Usage | Clé | TTL |
|---|---|---|
| Déduplication des webhooks | `dedup:{repo}:{pr}:{sha}` | 24 h |
| Rate limiting par dépôt | `ratelimit:{repo}` | Compteur, max 3 pipelines simultanés |
| Cache des résultats scanners | `scan:{nom_scanner}:{chemin_repo}` | 1 h |

Le cache scanners est la raison d'être de Redis ici. Sans cache, chaque PR rouvert ou *force-push* relancerait Trivy + Gitleaks + Semgrep en entier. Avec le cache, si le contenu du repo n'a pas changé (même `head_sha`), les résultats sont resservis instantanément — gain : 4 à 6 minutes par PR.

### 3.5 `nginx` — point d'entrée unique

**Image :** `nginx:alpine`.
**Ports :** 80 (HTTP) et 443 (mais TLS non configuré — connexions silencieusement closes via `return 444`).
**RAM consommée :** ≈ 3 Mo.

Reverse proxy qui multiplexe sept routes différentes vers les services internes :

| Chemin externe | Service interne | Particularités |
|---|---|---|
| `GET /` | redirige vers `/ui` | Page d'accueil = chat |
| `GET /ui` | `agent:8000/ui` | **Auth basic** via `.htpasswd` — interface chat |
| `/chat/` | `agent:8000/chat/` | **SSE** — `proxy_buffering off`, `proxy_read_timeout 1800s` |
| `/api/` | `agent:8000/` | API générale de l'agent, timeout 600 s |
| `/webhooks/github` | `agent:8000/webhooks/github` | Transmet les en-têtes GitHub (`X-Hub-Signature-256`, `X-GitHub-Event`, `X-GitHub-Delivery`) |
| `/callbacks/slack` | `agent:8000/callbacks/slack` | Reprise du pipeline après validation humaine |
| `/grafana/` | `grafana:3000` | WebSocket pour les dashboards live |
| `/prometheus/` | `prometheus:9090` | UI Prometheus avec préfixe configuré côté serveur |
| `/jenkins/` | `jenkins:8080` | Avec `proxy_redirect` pour fixer les URLs absolues |
| `/health` | `agent:8000/health` | Sondage externe |

**Détail crucial pour SSE.** Le chat utilise *Server-Sent Events* (HTTP streaming long), pas WebSocket. Nginx doit donc désactiver `proxy_buffering`, fixer un `proxy_read_timeout` long (30 minutes pour couvrir le chargement à froid d'un 14B + la génération), et utiliser HTTP/1.1 (`proxy_http_version 1.1`). Sans ces réglages, le streaming token-par-token se bloque ou se coupe au bout de 60 secondes.

**Résolveur Docker.** La directive `resolver 127.0.0.11 valid=10s;` est posée en tête du bloc HTTP pour que Nginx ré-interroge le DNS interne de Docker toutes les 10 secondes. Sans elle, quand un conteneur est recréé et change d'IP, Nginx renvoie des 502 jusqu'à un redémarrage manuel.

### 3.6 `prometheus` — métriques + alertes

**Image :** `prom/prometheus:latest`.
**Port :** 9090 (exposé hôte sans authentification — point à corriger).
**RAM consommée :** ≈ 26 Mo.
**Rétention locale :** 30 jours.
**Préfixe d'URL :** `/prometheus/` (les chemins API sont préfixés).

Scrape 4 cibles toutes les 15 secondes :

| Job | Cible | Métriques |
|---|---|---|
| `devsecops-agent` | `devsecops-agent:8000/metrics` | HTTP latency/count, 28 métriques custom, métriques par conteneur (via le poller docker-stats de l'agent), `ollama_*`, `localai_*` |
| `node-exporter` | `172.20.0.1:9100` (gateway bridge) | CPU/RAM/disque/réseau hôte |
| `prometheus` | `localhost:9090/prometheus/metrics` | Auto-monitoring |
| `alertmanager` | `alertmanager:9093/alertmanager/metrics` | Auto-monitoring |

Chaque échantillon est aussi écrit en `remote_write` vers VictoriaMetrics, ce qui permet de garder un historique de 90 jours sans saturer le TSDB local.

12 règles d'alerte définies dans `prometheus/alerts.rules.yml`, groupées en cinq familles : disque (4 alertes), hôte (3), agent (3), Ollama (2), LocalAI (3). Les alertes critiques (DiskCritical, HostHighMemory, AgentDown, OllamaDown) ont des fenêtres `for` courtes (1 à 2 min) ; les alertes info (LocalAINoModelsInstalled, AgentReviewBacklog) sont volontairement tolérantes (30 min à 24 h).

### 3.7 `alertmanager` — routage des alertes

**Image :** `prom/alertmanager:latest`.
**Port :** 9093 (exposé hôte sans authentification).
**RAM consommée :** ≈ 10 Mo.

Reçoit les alertes de Prometheus et les route vers l'agent via un webhook unique :

```yaml
receivers:
  - name: agent-webhook
    webhook_configs:
      - url: http://devsecops-agent:8000/webhooks/alertmanager
        send_resolved: true
        max_alerts: 10
```

Trois règles de routage par sévérité :

| `severity` | `repeat_interval` |
|---|---|
| `critical` | 1 h (notification renvoyée toutes les heures tant que l'alerte est active) |
| `info` | 24 h |
| autres | 4 h |

Trois règles d'**inhibition** évitent le bruit pendant les incidents en cascade : si `AgentDown` est actif, les alertes `AgentHighErrorRate` et `AgentReviewBacklog` sont supprimées ; si `OllamaDown` est actif, `OllamaNoModelLoaded` est supprimée ; etc.

### 3.8 `grafana` — visualisation

**Image :** `grafana/grafana:latest`.
**Port :** 3000 (exposé hôte, protégé par mot de passe admin).
**RAM consommée :** ≈ 96 Mo.

Trois dashboards provisionnés automatiquement via les fichiers dans `grafana/provisioning/` :

1. **VPS Overview** — CPU, RAM, disque, réseau, charge système. Source : node-exporter.
2. **Agent & Pipeline** — durée des revues, distribution des verdicts, cache hits, erreurs, latence LLM. Source : métriques custom de l'agent.
3. **Containers & LLM** — CPU/RAM par conteneur (via docker-stats poller), modèles Ollama / LocalAI chargés. Source : métriques custom de l'agent.

Grafana est configuré avec deux datasources : Prometheus (récent) et VictoriaMetrics (historique). Ce qui permet de zoomer rapidement à 5 minutes ou de regarder l'évolution sur 90 jours sans changer de dashboard.

### 3.9 `victoriametrics` — stockage long terme

**Image :** `victoriametrics/victoria-metrics:latest`.
**Port :** 8428 (exposé hôte sans authentification).
**RAM consommée :** ≈ 97 Mo.
**Rétention :** 90 jours.

Reçoit le `remote_write` de Prometheus. Compatible API Prometheus, donc Grafana peut l'interroger transparemment. Coût disque environ 5× plus faible que Prometheus pour la même rétention grâce à un encodage temporel plus compact.

**Anecdote utile à mentionner si l'encadrant demande la robustesse :** Victoria avait été silencieusement cassée pendant neuf jours en avril, le remote_write échouait sans alerter. C'est ce qui a motivé la mise en place de la règle `OllamaNoModelLoaded` et l'amélioration de l'audit VPS du Sprint 8.

### 3.10 `jenkins` — CI/CD

**Image :** construite depuis `./jenkins/Dockerfile`.
**Ports :** 8080 (web UI), 50000 (agents JNLP).
**RAM consommée :** ≈ 1 Go (le plus gourmand après Ollama).

Sert à construire les images Docker des projets surveillés et à exécuter des tests pré-merge. Tourne avec accès au socket Docker pour le Docker-in-Docker. Pas encore intégré au pipeline de revue (la revue est déclenchée par le webhook GitHub, pas par Jenkins) — mais Jenkins est positionné pour reprendre le rôle de gate CI/CD bloquant si le score de risque est CRITICAL.

### 3.11 `open-webui` — interface graphique pour Ollama

**Image :** `ghcr.io/open-webui/open-webui:main`.
**Port :** 3001 (exposé hôte).
**RAM consommée :** ≈ 300 Mo.

Interface ChatGPT-like qui se connecte directement à Ollama (`OLLAMA_BASE_URL=http://ollama:11434`). Utile pour tester les modèles à la main, comparer Qwen et Llama sur un même prompt, ou montrer à un visiteur ce que l'IA produit. **N'a aucun rôle dans le pipeline PR review** — c'est purement un outil d'inspection.

### 3.12 `node-exporter` — métriques hôte

**Image :** `prom/node-exporter:latest`.
**Particularité :** tourne en `network_mode: host` + `pid: host` pour voir les vrais processus et interfaces réseau du noyau.
**RAM consommée :** ≈ 10 Mo.

Expose les métriques classiques `node_cpu_seconds_total`, `node_memory_*`, `node_filesystem_*`, `node_load1`, etc. Sans lui, Prometheus n'aurait aucun moyen de mesurer la charge réelle du VPS (le `agent_disk_used_percent` exposé par l'agent est un *fallback* en cas d'indisponibilité de node-exporter, mais c'est moins précis).

### 3.13 `localai` — sandbox d'inférence (post-Sprint 8)

**Image :** `localai/localai:latest-cpu`.
**Port :** 8081 (exposé hôte, route vers le port 8080 interne du conteneur).
**RAM consommée :** ≈ 4–8 Go selon le modèle chargé.
**Limite Docker :** 24 Go.

Backend d'inférence alternatif compatible API OpenAI, déployé en sandbox via un compose séparé (`docker-compose.localai.yml`). Charge des GGUF directement depuis HuggingFace (par exemple `huggingface://bartowski/Qwen2.5-Coder-7B-Instruct-GGUF/...-Q4_K_M.gguf`). Le router chat de l'agent peut le cibler via le préfixe `localai/<nom>` dans l'identifiant du modèle.

**Pourquoi cette sandbox ?** Pour valider directement que le choix d'Ollama tenait face à une alternative. Le benchmark croisé sur le même modèle `qwen2.5-coder:7b` Q4_K_M a donné Ollama à 5,49 tok/s contre LocalAI à 4,50 tok/s — Ollama 22 % plus rapide. Le pipeline production reste donc sur Ollama, mais l'abstraction du backend est désormais validée et permet de tester rapidement vLLM, llama.cpp server, ou d'autres engines à l'avenir.

---

## 4. Communication entre conteneurs

Cette section explique comment chaque flux traverse l'architecture. À mémoriser : *qui parle à qui, par quel protocole, et pourquoi*.

### 4.1 Le DNS interne de Docker

Tous les conteneurs (sauf node-exporter) sont sur le réseau `devsecops_devsecops-net`. Docker fournit un résolveur DNS interne sur `127.0.0.11` : chaque conteneur peut joindre n'importe quel autre par son nom. Donc `postgres`, `redis`, `ollama`, `devsecops-agent`, etc. sont des noms d'hôtes valides à l'intérieur du réseau, sans préciser de port.

Cela évite de coder en dur les adresses IP (qui changent à chaque recréation du conteneur) et de devoir maintenir un fichier `hosts` ou un service discovery externe.

### 4.2 Flux nº 1 — Revue d'une Pull Request (le flux principal)

```
1. Développeur ouvre une PR sur GitHub
        │
        ▼
2. GitHub envoie un POST sur https://vps-bte/webhooks/github
   avec header X-Hub-Signature-256 (HMAC du body avec le secret partagé)
        │
        ▼
3. Nginx reçoit la requête sur :80, valide pas la signature (c'est l'agent
   qui le fait), transmet à devsecops-agent:8000
        │
        ▼
4. devsecops-agent (router webhooks) :
   - vérifie la signature HMAC-SHA256
   - lance un asyncio.create_task() pour le pipeline (réponse 202 immédiate à GitHub)
   - démarre le workflow LangGraph "pr_review"
        │
        ▼
5. Nœud intake — l'agent parle à :
   - redis (SET NX pour la déduplication, GET pour le rate limit)
   - github.com via httpx (POST commentaire "in progress")
   - le système de fichiers local (git clone via subprocess)
   - postgres (SELECT du repo_history)
        │
        ▼
6. Nœud classify — l'agent appelle ollama:11434/api/chat
   avec qwen2.5-coder:7b, format JSON forcé
        │
        ▼
7. Nœuds scan_full / scan_fs — l'agent lance en parallèle (asyncio.gather) :
   - Trivy (subprocess) qui scanne le repo cloné et éventuellement l'image Docker
   - Gitleaks (subprocess)
   - Semgrep (subprocess) — selon classification
   - Checkov (subprocess) — selon classification
   - OSV-Scanner (subprocess) — selon classification
   Avant chaque appel, vérifie le cache redis (clé scan:{nom}:{path}).
   Après chaque appel, met en cache Redis (TTL 1h) et sauve dans ./artifacts/.
        │
        ▼
8. Nœud analyze_review — l'agent appelle ollama:11434/api/chat avec
   qwen2.5-coder:14b, prompt combinant le diff annoté et les résumés
   scanners. Sortie : markdown de revue + JSON {risk_score, verdict,
   code_review_summary, comments[]}.
        │
        ▼
9. L'agent parle à :
   - github.com (POST /repos/{r}/pulls/{n}/reviews avec body markdown + comments[])
   - postgres (INSERT dans pr_reviews + UPDATE repo_profiles)
   - ./artifacts/scans/{repo}/pr-{n}/summary.json (écriture disque)
        │
        ▼
10. Nœud report — l'agent poste un commentaire final sur la PR avec
    le score de risque. Si CRITICAL ou HIGH et SLACK_ESCALATION_ENABLED=true,
    le pipeline s'arrête sur "escalate" (interrupt_before — checkpoint dans Postgres)
    et envoie un message Slack avec un bouton "Approve" ; la reprise se fait
    via /callbacks/slack quand le humain clique.
```

Temps cumulé typique : 6 à 11 minutes selon la taille du diff et la classification (les PR `docs` font 30 secondes parce que `skip_scan` court-circuite tout).

### 4.3 Flux nº 2 — Conversation chat (assistant ops)

```
1. L'utilisateur (toi ou l'encadrant) ouvre http://vps-bte/ui
        │
        ▼
2. Nginx demande l'auth basic (.htpasswd), puis transmet à agent:8000/ui
        │
        ▼
3. L'agent renvoie une page HTML statique avec JavaScript qui ouvre
   un POST /chat/stream en SSE
        │
        ▼
4. Le router chat lance la boucle ReAct :
   - System prompt (identité "BTE Security AI Agent" + règles anti-hallucination)
   - Pré-validation _looks_like_tool_call() pour détecter une intention d'outil
   - Appel ollama:11434 avec qwen2.5-coder:14b OU localai:8080/v1 selon
     le préfixe du modèle choisi
        │
        ▼
5. Si le LLM produit un JSON {"name": "...", "arguments": {...}} :
   - L'agent dispatche vers une des 20 fonctions @tool dans ops_assistant/tools.py
   - L'outil exécute en synchrone : subprocess (ps, df), httpx vers
     prometheus:9090, psycopg vers postgres, redis-py vers redis,
     httpx vers docker.sock pour les container_*, etc.
   - Le résultat (JSON ou texte) est ré-injecté dans le prompt comme
     "Observation: ..."
        │
        ▼
6. L'agent renvoie chaque token au navigateur via SSE :
   - event "thinking" pendant que le LLM réfléchit
   - event "tool_start" / "tool_end" quand un outil est appelé
   - event "token" pour chaque morceau de texte généré
   - event "done" en fin de réponse
```

Particularité du chat : le pipeline PR review ne touche jamais le chat (et inversement). C'est le même `devsecops-agent` mais deux routers différents, deux modèles différents potentiellement, et des prompts complètement distincts.

### 4.4 Flux nº 3 — Une alerte Prometheus déclenche une action

```
1. Prometheus scrape devsecops-agent:8000/metrics et détecte par exemple
   agent_disk_used_percent > 90 pendant 2 minutes
        │
        ▼
2. La règle DiskCritical passe en "firing"
        │
        ▼
3. Prometheus envoie l'alerte à alertmanager:9093/alertmanager/api/v2/alerts
        │
        ▼
4. AlertManager regroupe par alertname/severity (group_wait 30s pour
   éviter le spam), applique les règles d'inhibition, puis POSTe sur
   http://devsecops-agent:8000/webhooks/alertmanager (jusqu'à 10 alertes
   batchées par payload)
        │
        ▼
5. Le router webhooks de l'agent :
   - parse le payload AlertManager
   - log via structlog
   - pour chaque alerte critique disque : lance docker builder prune
   - envoie un message Slack via slack_api.send_notification()
        │
        ▼
6. Slack reçoit le message avec le détail de l'alerte et l'action effectuée
```

C'est l'**autonomie opérationnelle** : aucune intervention humaine n'est nécessaire pour libérer du disque ou pour être notifié. Le scheduler fait le même travail en *prévention* toutes les 30 minutes ; AlertManager fait le travail en *réaction* dès que le seuil est franchi.

### 4.5 Flux nº 4 — Métriques et observabilité

```
                   toutes les 15 secondes
                            │
                            ▼
   devsecops-agent:8000/metrics  ◄── scrape ── Prometheus:9090
                            │                       │
                            │                       │ remote_write
                            │                       ▼
                            │              VictoriaMetrics:8428
                            │
                            │                       ▲
                            │                       │ datasource
                            │                       │
                            │                   Grafana:3000  ◄── navigateur
                            │                       ▲
                            │                       │ datasource
                            │                       │
                            └────────── Prometheus (récent) ──┘

   node-exporter:9100 ◄── scrape ── Prometheus:9090  (même chemin)
```

Côté agent, le module `app.metrics.custom` déclare 28 métriques Prometheus :

| Famille | Métriques |
|---|---|
| Pipeline | `agent_reviews_total`, `agent_pipeline_duration`, `agent_scan_duration`, `agent_llm_duration` |
| Cache | `agent_cache_hits`, `agent_cache_misses` |
| Erreurs | `agent_errors_total` |
| Disque | `agent_disk_used_percent`, `agent_disk_free_gb` |
| Ollama | `ollama_reachable`, `ollama_model_loaded`, `ollama_model_size_bytes`, `ollama_model_vram_bytes`, `ollama_models_loaded_total` |
| LocalAI | `localai_reachable`, `localai_models_total`, `localai_health_check_latency_seconds`, `localai_model_installed`, `localai_model_size_gb` |
| Conteneurs | `container_running`, `container_memory_bytes`, `container_memory_limit_bytes`, `container_cpu_percent`, `container_network_rx_bytes`, `container_network_tx_bytes` |

---

## 5. L'agent en détail — anatomie du code

Le répertoire `agent/app/` est organisé comme une application FastAPI moderne :

```
agent/app/
├── main.py              ← point d'entrée (lifespan, routers, pollers)
├── config.py            ← settings Pydantic chargés depuis .env
├── engine/
│   ├── checkpointer.py  ← AsyncPostgresSaver pour LangGraph
│   ├── dispatcher.py    ← route les événements vers le bon workflow
│   └── registry.py      ← register_all_workflows() — compile les 7 graphes
├── llm/
│   └── ollama.py        ← 4 factory functions + circuit breaker LLM
├── routers/
│   ├── webhooks.py      ← POST /webhooks/github, /webhooks/alertmanager
│   ├── callbacks.py     ← POST /callbacks/slack
│   ├── health.py        ← GET /health, /metrics
│   └── chat.py          ← GET /ui, /chat/models ; POST /chat/stream (SSE)
├── workflows/
│   ├── pr_review/       ← le pipeline principal (9 nœuds)
│   ├── ops_assistant/   ← 20 outils utilisés par le chat
│   ├── compliance_drift/
│   ├── cve_watch/
│   ├── incident_triage/
│   ├── pipeline_gate/
│   └── scheduled_audit/
├── services/
│   ├── trivy_service.py     ← wrapper subprocess Trivy
│   ├── gitleaks_service.py
│   ├── semgrep_service.py
│   ├── checkov_service.py
│   ├── osv_service.py
│   ├── git_service.py        ← clone, diff -U15, truncation
│   ├── docker_service.py     ← build d'image pour Trivy image
│   ├── github_api.py         ← post comment, post review, etc.
│   ├── slack_api.py
│   ├── knowledge.py          ← INSERT/SELECT vers postgres
│   ├── cache.py              ← redis (dedup, rate limit, scan cache)
│   ├── diff_parser.py        ← parse_diff() — utilisé pour mapper commentaires inline
│   ├── artifact_store.py     ← écriture des raw JSON sous ./artifacts/
│   └── scheduler.py          ← disk_guard + health_digest
├── prompts/
│   ├── classifier.py
│   ├── security_review.py
│   ├── code_review.py
│   ├── combined_review.py
│   └── templates.py          ← formatage des résultats scanners
├── models/
│   └── state.py              ← AgentState (parent), PRReviewState (enfant)
└── metrics/
    └── custom.py             ← les 28 jauges/counters/histogrammes Prometheus
```

### 5.1 Cycle de vie de l'application (`main.py`)

Au démarrage (`lifespan` de FastAPI) :

1. Initialise Redis (graceful — le pipeline tourne dégradé si Redis est down).
2. Initialise le `AsyncPostgresSaver` et fait son `setup()` (création des tables LangGraph si absentes).
3. Initialise le pool psycopg pour le service `knowledge` (séparé du checkpointer).
4. Vérifie la connectivité Ollama (log un warning si injoignable).
5. Compile et enregistre les 7 workflows via `register_all_workflows()`.
6. Démarre 4 tâches asynchrones en arrière-plan : Ollama poller, LocalAI poller, Docker stats poller, scheduler.

À l'arrêt : annule toutes les tâches, ferme proprement les connexions Redis et Postgres.

### 5.2 Le pipeline PR Review en détail (`workflows/pr_review/`)

Quatre fichiers seulement :

| Fichier | Rôle |
|---|---|
| `state.py` | Déclaration de `PRReviewState` (TypedDict) — toutes les clés que les nœuds lisent et écrivent. |
| `nodes.py` | Les 9 fonctions de nœud (`intake_node`, `classify_node`, `scan_full_node`, `scan_fs_node`, `skip_scan_node`, `analyze_review_node`, `escalate_node`, `report_node`, `error_node`). 1 224 lignes. |
| `edges.py` | Les deux fonctions de routage conditionnel (`route_scans`, `route_risk`). |
| `graph.py` | Construit et compile le `StateGraph` avec checkpointer et `interrupt_before=["escalate"]`. |

**Les 9 nœuds, ce qu'ils font (à mémoriser) :**

1. **`intake_node`** — Dédup Redis, rate limit, post du commentaire "in progress" sur GitHub, clone du repo, génération du diff `-U15` local, détection Dockerfile, extraction des fichiers changés, lecture du `repo_history`.
2. **`classify_node`** — Appelle le 7B avec `format="json"` et reçoit `{"classification": "...", "risk_hint": "..."}`. Cinq classes : `feature`, `dependency`, `infrastructure`, `docs`, `config`. *Fallback regex* si le circuit breaker LLM est ouvert.
3. **`scan_full_node`** — Si `has_dockerfile == True` : build l'image (`docker build`) puis lance en parallèle Trivy FS + Gitleaks + Trivy image + (Semgrep|Checkov|OSV selon classification).
4. **`scan_fs_node`** — Pas de Dockerfile : lance en parallèle Trivy FS + Gitleaks + (Semgrep|Checkov|OSV selon classification).
5. **`skip_scan_node`** — PR `docs` : ne fait rien, passe au nœud d'analyse.
6. **`analyze_review_node`** — Appelle le 14B avec le diff annoté, les résumés scanners, le `repo_history`. Sortie : markdown de revue + JSON `{risk_score, verdict, code_review_summary, comments[]}`. Poste la revue GitHub avec commentaires *inline*. Persiste dans `pr_reviews`. *Fallback dégradé* (revue basée scanners seuls) si le LLM échoue.
7. **`escalate_node`** — Marqué `interrupt_before` : checkpoint dans Postgres, message Slack avec bouton Approve. Le pipeline est suspendu jusqu'à `POST /callbacks/slack` qui le reprend.
8. **`report_node`** — Commentaire de synthèse final sur la PR, mise à jour du `commit status`, écriture de `summary.json` dans `./artifacts/`.
9. **`error_node`** — Toute exception non rattrapée pose `state["error"]` ; un edge conditionnel route alors vers ce nœud qui logue et termine proprement.

**Le routage conditionnel.** Deux fonctions dans `edges.py` :

```python
def route_scans(state):
    if state.get("error"): return "error_node"
    if state["pr_classification"] == "docs": return "skip_scan"
    if state.get("has_dockerfile"): return "scan_full"
    return "scan_fs"

def route_risk(state):
    if state.get("error"): return "error_node"
    if state["risk_score"] in ("CRITICAL", "HIGH") and SLACK_ENABLED:
        return "escalate"
    return "report"
```

### 5.3 La matrice de scanners

```python
SCAN_MATRIX = {
    "feature":        {"semgrep"},
    "dependency":     {"osv"},
    "infrastructure": {"checkov"},
    "config":         set(),
    "docs":           set(),
}
```

Trivy FS + Gitleaks tournent **toujours** (sauf `docs`). Le scanner supplémentaire dépend du verdict du classifier. Une PR `feature` voit donc tourner Trivy + Gitleaks + Semgrep ; une PR `dependency` voit tourner Trivy + Gitleaks + OSV-Scanner ; une PR `infrastructure` voit tourner Trivy + Gitleaks + Checkov. Cette matrice évite de lancer Semgrep (qui peut prendre 2 minutes) sur une PR qui ne touche que `requirements.txt`.

### 5.4 Le diff annoté pour les commentaires inline

Particularité subtile mais importante. GitHub n'accepte un commentaire *inline* que si la ligne référencée est présente dans le diff de la PR. L'agent ne peut donc pas inventer des numéros de ligne. Trois mécanismes coopèrent :

1. **Diff local `-U15`.** Au lieu de la diff GitHub API (`-U3`, trois lignes de contexte), l'agent fait `git clone` puis `git diff -U15 FETCH_HEAD..HEAD`. Quinze lignes de contexte autour de chaque changement, ce qui donne au LLM les imports et le contexte voisin pour bien suggérer.
2. **Diff annoté avec numéros de ligne.** Le module `services/diff_parser.py` parse le diff unifié et le re-formate avec un préfixe `Lxxxx |` devant chaque ligne. Le LLM voit donc explicitement `L42 |   query = f"SELECT * FROM users WHERE id={user_id}"`.
3. **Validation des lignes côté agent.** Avant de POST sur GitHub, `analyze_review_node` filtre les commentaires dont la `line` n'apparaît pas dans le `diff_lines_for_file()` du diff parsé. Si le LLM hallucine une ligne, le commentaire est silencieusement écarté plutôt que de produire une erreur GitHub.

### 5.5 Le circuit breaker LLM

Dans `app/llm/ollama.py`, trois fonctions exposées (`is_circuit_open`, `record_llm_failure`, `record_llm_success`) maintiennent un compteur d'échecs glissant. Si Ollama échoue 5 fois de suite, le breaker s'ouvre pour 60 secondes. Pendant cette période, `classify_node` repasse sur la classification regex et `analyze_review_node` produit une revue *dégradée* basée uniquement sur les résultats scanners. C'est ce qui garantit que **le pipeline ne se bloque jamais** même si Ollama crashe en plein milieu.

### 5.6 Le chat ops — boucle ReAct

Dans `routers/chat.py`, l'agent implémente une boucle ReAct *à la main* (sans LangGraph) pour avoir le contrôle total du streaming SSE.

```
       ┌──────────────┐
       │  system prompt
       │  + history   │
       │  + user msg  │
       └──────┬───────┘
              ▼
         LLM (Ollama ou LocalAI selon préfixe du modèle)
              │
              ▼
       ┌──────────────────────────────────────┐
       │ Parse réponse :                      │
       │  - Contient un JSON tool call ?      │
       │  - Tool name ∈ liste autorisée ?     │
       └──────┬───────────────────────────────┘
              │ non → renvoyer le texte au client (SSE token events)
              │
              │ oui
              ▼
       ┌──────────────────────────────────────┐
       │ Exécute le tool (ops_assistant/tools)│
       │ Envoie events SSE :                  │
       │   tool_start, tool_end               │
       │ Met le résultat en cache (TTL 10-120s│
       │ selon la fraîcheur attendue)         │
       └──────┬───────────────────────────────┘
              ▼
       ┌──────────────────────────────────────┐
       │ Ré-injecte dans le prompt :          │
       │  "Observation: <résultat JSON>"      │
       │ Boucle au LLM                        │
       └──────────────────────────────────────┘
```

**Anti-hallucination — 6 couches en place :**

1. `temperature=0.0` sur le chat (déterministe).
2. `num_ctx=6144` (volontairement modeste pour réduire la dérive sur longs contextes).
3. Garde *sans-outil* : si l'utilisateur pose une question factuelle qui ne nécessite pas d'outil (ex. "comment marche un webhook ?"), le LLM répond directement sans inventer un appel d'outil.
4. Bloc système qui interdit explicitement de fabriquer des données.
5. Injection des résultats d'outil comme `Observation: ...` pour ancrer la réponse dans des faits réels.
6. `num_predict=800` cap pour éviter les fins de réponse divagantes.

**Les 20 outils dans `workflows/ops_assistant/tools.py` :**

| Famille | Outils |
|---|---|
| Système hôte | `vps_status`, `disk_usage`, `top_processes`, `network_stats`, `system_net_io` |
| Conteneurs | `list_containers`, `container_logs`, `container_stats`, `inspect_container`, `list_images`, `restart_service` |
| LLM | `ollama_status` |
| Observabilité | `query_prometheus`, `query_prometheus_range`, `prometheus_alerts` |
| Cache + base | `redis_info`, `query_database` |
| CI/CD | `jenkins_status` |
| Artefacts | `list_scan_artifacts`, `read_scan_artifact` |

Tous **en lecture seule** sauf `restart_service` qui a une *whitelist* (impossible de restart `postgres` ou `redis` via le chat). Tous synchrones (subprocess, psycopg sync, redis-py sync, httpx sync) parce que la boucle ReAct n'est pas asynchrone — ce qui rend le code plus simple à lire.

---

## 6. État actuel du VPS (snapshot pour la soutenance)

À mentionner si l'encadrant demande "et concrètement, ça tourne ?" :

| Indicateur | Valeur |
|---|---|
| Conteneurs `Up` | 13 / 13 |
| Conteneurs `healthy` | 9 (les 4 autres n'ont pas de healthcheck, leur santé est vérifiée via Prometheus) |
| Uptime hôte | 42 jours |
| Charge système | load average 0,64 / 0,50 / 0,41 — très calme |
| RAM utilisée | 15 Go / 45 Go |
| Disque utilisé | 124 Go / 290 Go (43 %) — bien en dessous des seuils d'alerte |
| Pas de swap configuré | C'est volontaire (Ollama performe mieux sans swap) |
| Modèles Ollama installés | 4 (qwen2.5-coder:7b, qwen2.5-coder:14b, llama3.2:3b, granite3.1-dense:2b) |

---

## 7. Sécurité — ce que tu peux dire (et ce qu'il faut reconnaître)

### Bonnes pratiques en place

- **Webhooks GitHub validés HMAC-SHA256.** Le secret est dans `.env`. Toute requête sans header `X-Hub-Signature-256` valide est rejetée 401.
- **Chat protégé par auth basic.** Les routes `/ui` et `/chat/` exigent les identifiants du `.htpasswd` monté en lecture seule dans Nginx.
- **Inférence 100 % locale.** Aucune sortie réseau vers une API LLM tierce (OpenAI, Anthropic, etc.). Le code source ne quitte jamais le VPS.
- **Segmentation Docker.** Les services à risque (postgres, ollama) ne sont pas exposés sur l'hôte — accessibles uniquement depuis le réseau `devsecops-net`.
- **Logs structurés.** Tous les logs en JSON via structlog, rotation 50 Mo × 10 fichiers, persistés dans `./artifacts/logs/`.
- **Pas de secrets en clair dans le code.** Tous les tokens et mots de passe transitent par `.env` puis Pydantic settings.

### Limites identifiées (à reconnaître ouvertement — ça montre la maturité)

Le chapitre 4 du rapport documente honnêtement les ports exposés sans authentification :

| Port hôte | Service | Risque | Correction prévue |
|---|---|---|---|
| 6379 | Redis | Accès distant possible sans mot de passe | Activer `requirepass` ou retirer le port hôte |
| 8428 | VictoriaMetrics | API de lecture/écriture exposée | Mettre derrière nginx avec auth basic |
| 9090 | Prometheus | UI accessible sans auth | Idem (la route nginx `/prometheus/` existe déjà mais le port direct reste ouvert) |
| 9093 | AlertManager | API silence/inhibit ouverte | Idem |
| 8000 | devsecops-agent | Endpoints `/health` et `/metrics` ouverts | Acceptable car pas de donnée sensible exposée |

Ces points sont **identifiés**, **documentés** et **planifiés** dans la suite. C'est aussi pour ça qu'on a ajouté Let's Encrypt (HTTPS) comme prochain chantier post-soutenance. Le rapport en parle dans la section "Limites identifiées et plan de durcissement" du chapitre 4.

---

## 8. La méthodologie — Scrumban (pour les questions sur le pilotage)

Le projet a été conduit sur 8 sprints de 2 semaines en méthodologie Scrumban avec WIP=1. Points à retenir :

- **Pourquoi Scrumban et pas Scrum pur ?** Un stage solo doit avaler les incidents de production sans casser le sprint. Kanban (avec ses limites WIP) donne cette souplesse ; Scrum apporte la cadence et les jalons visibles côté encadrement.
- **Pourquoi WIP=1 ?** Une seule tâche en cours à tout moment. Empêche le multitâche silencieux où plusieurs cartes traînent à 80 % sans avancer. Quand un incident arrive (disque saturé à 90 %, AlertManager silencieusement cassé, VictoriaMetrics tombée 9 jours), il devient la carte prioritaire immédiate et passe en *Expedite*.
- **Définition de terminé.** Cinq conditions cumulatives : déployé sur le VPS, logs propres, métriques cohérentes, événement réel déclenché et résultat conforme, documentation à jour. Si une seule manque, la carte ne passe pas en *Done*.
- **Les 5 jalons (M1–M5).** M1 = première PR analysée bout en bout (S2). M2 = revue LLM publiée sur GitHub avec 5 scanners (S4). M3 = autonomie opérationnelle (Slack + disk guard + scheduler, S5). M4 = observabilité complète (Prometheus + Grafana, S6). M5 = durcissement post-audit (S8).

---

## 9. Questions probables de l'encadrant et réponses préparées

> **Q1 : Pourquoi avoir choisi Ollama plutôt qu'une API cloud comme OpenAI ?**

Réponse : contrainte forte de confidentialité bancaire — le code source des PR ne doit pas quitter l'infrastructure de la BTE. Toute API externe est exclue d'emblée. Ollama tourne 100 % en local, en CPU, sans GPU, ce qui rend l'architecture déployable sur n'importe quel VPS standard. Le coût marginal d'une revue est nul une fois le serveur amorti.

> **Q2 : Pourquoi deux modèles (7B et 14B) au lieu d'un seul ?**

Réponse : classification et analyse profonde sont deux tâches très différentes. La classification est un problème simple (5 classes, sortie JSON courte, < 512 tokens), un modèle 7B la résout à 8–12 tok/s en moins de 30 secondes. L'analyse de sécurité combinée à la revue de code demande de raisonner sur tout le diff, intégrer les résultats de 5 scanners, produire un commentaire markdown structuré et localiser les problèmes ligne par ligne ; un 14B à 3–6 tok/s prend 6 à 11 minutes. Un seul modèle 14B pour les deux étapes coûterait du temps inutile sur la classification ; un seul 7B pour les deux n'aurait pas la finesse pour la revue.

> **Q3 : Pourquoi avoir gardé Ollama après le benchmark LocalAI ?**

Réponse : sur le même modèle (Qwen2.5-Coder 7B Q4_K_M), même matériel, même prompt, Ollama mesure 5,49 tok/s contre 4,50 tok/s pour LocalAI — soit 22 % plus rapide. Ollama tire un meilleur parti de la stack `libggml-cpu-haswell.so` avec Flash Attention et KV cache quantifié. LocalAI reste comme sandbox parce que l'abstraction du backend (préfixe `ollama/` vs `localai/` dans l'identifiant du modèle) est désormais validée — si demain vLLM ou llama.cpp server devient plus performant, le swap se fait sans toucher la boucle ReAct.

> **Q4 : Comment garantis-tu que la revue ne rate pas une vulnérabilité critique ?**

Réponse : trois couches en série. Premier filet : cinq scanners SAST déterministes (Trivy CVE + image, Gitleaks secrets, Semgrep OWASP, Checkov IaC, OSV dépendances) qui détectent les motifs connus avec zéro faux négatif sur leurs bases. Deuxième filet : le modèle 14B analyse le diff complet avec 15 lignes de contexte autour de chaque changement, ce qui lui permet de détecter des problèmes que les scanners ratent (logique métier, ordre d'appel, exposition de données via API). Troisième filet : score de risque et verdict bloquant — une PR avec score CRITICAL déclenche le `escalate_node` qui suspend le pipeline et exige une validation humaine via Slack.

> **Q5 : Que se passe-t-il si Ollama crashe en plein milieu d'une revue ?**

Réponse : le circuit breaker LLM s'ouvre après 5 échecs consécutifs. `classify_node` repasse alors sur un classifieur regex (analyse des extensions de fichiers). `analyze_review_node` construit une revue dégradée à partir des seuls résultats scanners (`_build_degraded_review`). La PR reçoit toujours un commentaire — explicitement marqué "Degraded Mode" — avec un verdict basé sur le total de findings CRITICAL/HIGH. Le checkpoint LangGraph dans Postgres garantit qu'en cas de crash complet de l'agent, le pipeline reprend exactement où il s'est arrêté à la prochaine relance.

> **Q6 : Pourquoi cAdvisor n'est pas utilisé pour les métriques par conteneur ?**

Réponse : Docker sur ce VPS utilise le snapshotter containerd, et cAdvisor (qui s'appuie sur l'image DB de Docker historique) renvoie des 500 dans cette configuration. La solution mise en place est un poller asyncio dans l'agent : toutes les 30 secondes, l'agent appelle `GET /containers/json` puis `GET /containers/{id}/stats?stream=false` sur le socket Docker, calcule CPU% et déduit les jauges `container_cpu_percent`, `container_memory_bytes`, `container_network_*_bytes`. Cela donne 100 % des métriques que cAdvisor aurait fournies, sans dépendance externe.

> **Q7 : Combien de temps une revue prend-elle en moyenne ?**

Réponse : 6 à 11 minutes pour une PR moyenne (200–500 lignes de diff, 5–15 fichiers, classification `feature`). Décomposition typique :
- Intake (clone + diff + repo history) : 15–30 s
- Classify (7B) : 20–40 s
- Scans en parallèle (Trivy + Gitleaks + Semgrep) : 90–180 s
- Analyze (14B sur 12 288 tokens de contexte) : 4–8 min
- Report : 5–10 s

Les PR `docs` font 30 secondes parce que `skip_scan_node` court-circuite tout.

> **Q8 : Pourquoi écrire à la fois dans Prometheus et VictoriaMetrics ?**

Réponse : Prometheus garde 30 jours en local, suffisant pour le débogage et les alertes. VictoriaMetrics garde 90 jours en `remote_write` pour les tendances de fond (évolution mensuelle du temps de revue, rapport mensuel CVE, etc.). Grafana interroge les deux datasources transparemment. Cela donne le meilleur des deux mondes : alerting réactif court terme + analyse historique long terme, sans saturer le TSDB local de Prometheus.

> **Q9 : Comment gères-tu les faux positifs des scanners ?**

Réponse : trois niveaux. Niveau 1 — les scanners eux-mêmes sont configurés avec leurs *baselines* par défaut, sans suppression agressive (mieux vaut un faux positif vu et écarté qu'un faux négatif silencieux). Niveau 2 — le LLM 14B reçoit les résultats des 5 scanners et les met en perspective : si Trivy signale une CVE dans une lib transitive jamais appelée, le LLM le contextualise et baisse le score. Niveau 3 — le `repo_history` injecté dans le prompt permet au LLM de voir les patterns déjà signalés sur les PR précédentes du même repo, ce qui évite de re-signaler à chaque PR le même point déjà accepté par les revieweurs.

> **Q10 : Quelle est la perspective d'évolution la plus crédible ?**

Réponse : trois axes complémentaires.
1. **Fine-tuning sur les CVE bancaires.** Un fine-tuning léger (LoRA) du 14B sur un corpus de CVE bancaires historiques améliorerait la détection des patterns sectoriels (manipulation de comptes, transferts SWIFT, vérification de signatures).
2. **Modèles plus récents.** Qwen3-Coder MoE (30B paramètres, 3B actifs) annoncé récemment promet un débit comparable au 14B avec une qualité proche du 32B — accessible via la sandbox LocalAI.
3. **Élargissement à d'autres événements.** Les workflows `compliance_drift`, `cve_watch`, `incident_triage`, `pipeline_gate`, `scheduled_audit` sont déjà esquissés mais peu remplis ; ils ouvrent la voie à un agent qui ne réagit pas seulement aux PR mais aussi aux dérives de conformité, aux nouvelles CVE publiées, et aux incidents Prometheus.

---

## 10. Aide-mémoire — phrases-clés à connaître par cœur

À ressortir si tu sèches sur une question :

- *"La contrainte forte est que le code source ne quitte jamais l'infrastructure de la BTE — c'est ce qui interdit toute API tierce et qui justifie l'inférence locale."*
- *"Le pipeline est asynchrone par construction : webhook GitHub → 202 immédiat → workflow en arrière-plan → commentaire posté sur la PR. GitHub n'attend jamais."*
- *"Les checkpoints LangGraph dans Postgres garantissent que le pipeline ne perd jamais d'état : reprise propre après crash, gate Slack possible sur les CRITICAL."*
- *"Le circuit breaker LLM fait que le pipeline ne s'arrête jamais : Ollama down → classification regex + revue scanner-only, mais une revue est toujours publiée."*
- *"L'observabilité couvre quatre cibles Prometheus, 12 alertes, 3 dashboards Grafana, 28 métriques custom et la rétention double (Prometheus 30j + VictoriaMetrics 90j)."*
- *"L'autonomie repose sur deux boucles dans le scheduler : disk_guard toutes les 30 minutes avec auto-cleanup au-delà de 90 %, et health_digest quotidien à 09:00 UTC vers Slack."*
- *"Le benchmark Ollama vs LocalAI a validé empiriquement le choix initial : 22 % plus rapide sur modèle identique, ce qui clôt la question 'aurions-nous dû prendre autre chose'."*
- *"La méthodologie Scrumban avec WIP=1 a tenu sur les 8 sprints sans replanification, même quand trois incidents production (urgence disque, AlertManager cassé, VictoriaMetrics tombée 9 jours) ont surgi."*

---

## 11. Ce qu'il NE faut pas dire / pièges à éviter

- **Ne pas dire** "le système est sécurisé" — il y a 5 ports exposés sans auth, c'est documenté comme un chantier de durcissement.
- **Ne pas dire** "Ollama est meilleur en absolu" — il est meilleur **sur ce matériel pour ces modèles**, prouvé par benchmark, pas dans tous les contextes.
- **Ne pas dire** "l'IA détecte toutes les vulnérabilités" — elle augmente la couverture, mais c'est la combinaison scanners + LLM qui fait le travail, et un humain garde le dernier mot sur les CRITICAL via Slack.
- **Ne pas confondre** Prometheus (récent, 30j) et VictoriaMetrics (long terme, 90j) — ce sont deux TSDB différents, le premier alimente le second en remote_write.
- **Ne pas confondre** cAdvisor (non utilisé) et le docker-stats poller (le mécanisme effectivement en place).
- **Ne pas confondre** Open WebUI (interface graphique pour Ollama, hors pipeline) et l'interface chat de l'agent (`/ui`, dans le pipeline, avec ReAct loop et 20 outils).

---

## 12. Plan de présentation suggéré (45 minutes)

| Minutes | Sujet | Slides cibles |
|---|---|---|
| 0–5 | Contexte BTE + problématique | Logo BTE + organigramme + diagramme "avant" |
| 5–10 | Architecture globale | Le grand diagramme du chapitre 2 du rapport |
| 10–18 | Pipeline PR review pas-à-pas | Topologie LangGraph 9 nœuds + matrice scanners |
| 18–25 | Démonstration live (si possible) | Ouvrir `/ui`, lancer une vraie PR sur un repo test |
| 25–30 | Observabilité + autonomie | Grafana dashboards + Slack alerts |
| 30–35 | Choix techniques justifiés | Tableau Ollama vs LocalAI, 7B vs 14B vs 32B |
| 35–40 | Limites + perspectives | Tableau hardening + Qwen3-Coder + fine-tuning |
| 40–45 | Questions / réponses | (Section 9 de ce document) |

---

## 13. Pour finir — ton mental

Le système marche, il tourne depuis 42 jours sans intervention, il a survécu à trois incidents documentés, il publie des revues réelles sur des PR réelles. Tu n'as pas à le défendre — tu as à l'expliquer. L'encadrant cherche à comprendre comment tu raisonnes, pas à te coller.

Si tu sèches sur une question : *"Bonne question, laissez-moi reformuler pour être sûr de bien y répondre"* — et tu reprends le fil. Tu connais ce système mieux que quiconque dans la pièce.

Bonne soutenance.
