# 03 — Observabilité : Prometheus, VictoriaMetrics, Grafana, AlertManager, node-exporter

> Objectif : expliquer la chaîne de monitoring de bout en bout et savoir répondre à « pourquoi deux bases de métriques ? », « comment l'agent se surveille lui-même ? », « que se passe-t-il quand le disque se remplit ? ».

---

## 1. La chaîne complète (à dessiner mentalement)

```
   CIBLES                  COLLECTE            STOCKAGE            VISU / ACTION
┌───────────┐
│ agent:8000│──/metrics──┐
│ /metrics  │            │
├───────────┤            │   ┌────────────┐  remote_write  ┌────────────────┐
│node-export│──:9100─────┼──▶│ prometheus │───────────────▶│ victoriametrics│ (90j)
│ (hôte)    │            │   │  (30j)     │                └────────────────┘
├───────────┤            │   └─────┬──────┘                         │
│alertmanager──/metrics──┘         │ évalue 15 règles               │
└───────────┘                      ▼                                ▼
                              ┌────────────┐                  ┌──────────┐
                              │alertmanager│                  │ grafana  │ (3 dashboards)
                              └─────┬──────┘                  └──────────┘
                          ┌─────────┴──────────┐         datasources : Prometheus,
                          ▼                    ▼          VictoriaMetrics, PostgreSQL
                       Slack            agent /webhooks/alertmanager
                    (humain)             (auto-remédiation disque)
```

---

## 2. Qui collecte quoi

**Prometheus** scrape toutes les **15 s** (`scrape_interval: 15s`) :
- `devsecops-agent:8000/metrics` — les métriques applicatives + business
- `node-exporter` via `172.20.0.1:9100` — l'hôte (CPU, RAM, disque, I/O)
- lui-même et `alertmanager`

> **Détail à connaître** : node-exporter est joint via `172.20.0.1` (gateway du bridge) et non par son nom de service, parce qu'il tourne en `network_mode: host`.

> **Pourquoi pas cAdvisor ?** Docker sur cet hôte utilise le *containerd snapshotter*, incompatible avec l'intégration image-DB de cAdvisor. Les métriques par conteneur (`container_cpu_percent`, `container_memory_bytes`…) sont donc produites par un **poller maison** dans l'agent qui lit `docker stats` toutes les 30 s. C'est un changement d'approche assumé (Sprint 6).

---

## 3. Pourquoi DEUX bases de métriques (Prometheus + VictoriaMetrics)

C'est une question très probable. Réponse :
- **Prometheus** garde **30 jours** en local : c'est le moteur temps réel + évaluation des règles d'alerte.
- **VictoriaMetrics** reçoit tout en `remote_write` et garde **90 jours** : stockage long terme, bien plus compact et performant en disque que Prometheus seul.
- Les deux sont des **datasources Grafana**, donc on peut afficher l'un ou l'autre selon la fenêtre de temps voulue.

---

## 4. Les métriques custom de l'agent (`metrics/custom.py`)

L'agent ne se contente pas de métriques techniques : il expose des métriques **métier**. À citer :

**Pipeline / business**
- `agent_reviews_total{risk_score, verdict}` — nb de revues, par niveau de risque et verdict
- `agent_pipeline_duration_seconds` — durée totale d'une revue (buckets jusqu'à 600 s)
- `agent_llm_duration_seconds{model, node}` — temps passé dans chaque appel LLM
- `agent_scan_duration_seconds{scanner}` — temps de chaque scanner
- `agent_errors_total{stage}` — erreurs par étape
- `agent_cache_hits_total` — efficacité du cache Redis

**Système**
- `agent_disk_used_percent`, `agent_disk_free_gb`
- `container_running`, `container_cpu_percent`, `container_memory_bytes` (par conteneur)

**Ollama / LocalAI**
- `ollama_reachable`, `ollama_model_loaded{model}`, `ollama_model_vram_bytes`
- `localai_reachable`, `localai_health_check_latency_seconds` (sandbox optionnelle)

**À dire** : « Je peux répondre à des questions métier directement en PromQL : combien de PR jugées CRITICAL ce mois-ci, quel scanner est le plus lent, le taux d'erreur du pipeline. »

---

## 5. Les 15 règles d'alerte (`prometheus/alerts.rules.yml`)

| Alerte | Sévérité | Déclencheur |
|---|---|---|
| `DiskWarning` / `DiskCritical` | warning / critical | disque hôte qui se remplit |
| `AgentDiskWarning` / `AgentDiskCritical` | warning / critical | disque vu par l'agent |
| `HostHighCPU` | warning | CPU hôte élevé |
| `HostHighMemory` | critical | RAM hôte élevée |
| `HostDiskIOHigh` | warning | I/O disque élevés |
| `AgentDown` | critical | l'agent ne répond plus |
| `AgentHighErrorRate` | warning | taux d'erreur du pipeline |
| `AgentReviewBacklog` | info | file de revues en attente |
| `OllamaDown` | critical | serveur LLM injoignable |
| `OllamaNoModelLoaded` | info | aucun modèle chargé |
| `LocalAISandboxDown` / `LocalAINoModelsInstalled` / `LocalAIHealthCheckSlow` | info | sandbox optionnelle |

---

## 6. La boucle autonome : que se passe-t-il quand le disque sature

C'est **le** scénario à raconter pour montrer l'autonomie :

1. Le disque dépasse le seuil → **node-exporter** le mesure → **Prometheus** évalue la règle `DiskCritical`.
2. Prometheus pousse l'alerte vers **AlertManager**.
3. AlertManager route en **double** : (a) notification **Slack** pour l'humain, (b) `POST /webhooks/alertmanager` vers l'**agent**.
4. L'agent reconnaît `DiskCritical`/`AgentDiskCritical` et lance **`docker builder prune -f`** → libère l'espace **sans intervention humaine**.

En complément, le **scheduler** de l'agent fait une vérification proactive du disque **toutes les 30 min** (seuil 80 % = warning Slack, 90 % = prune + alerte critique). Et un **health digest** quotidien (09:00 UTC) résume sur Slack l'état disque, conteneurs, Ollama et alertes actives.

> **Anecdote réelle à mentionner** : un incident disque survenu pendant le projet (avril 2026) est précisément ce qui a motivé cette boucle de garde.
