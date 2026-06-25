# 02 — Le code de l'agent : structure et logique

> Objectif : ouvrir le code en direct et expliquer **comment c'est organisé** et **pourquoi**, du `main.py` jusqu'au workflow LangGraph nœud par nœud.

---

## 1. Arborescence du code (`agent/app/`)

```
agent/app/
├── main.py              # point d'entrée FastAPI : lifespan, montage des routers, /metrics
├── config.py            # configuration (Pydantic Settings) : modèles, DSN, secrets
│
├── routers/             # les endpoints HTTP
│   ├── webhooks.py      #   POST /webhooks/github  (+ /webhooks/alertmanager)
│   ├── chat.py          #   POST /chat/stream (SSE), /chat/models, /ui
│   ├── callbacks.py     #   callbacks boutons Slack (reprise du graphe en pause)
│   └── health.py        #   /health, /readiness
│
├── workflows/           # les graphes LangGraph
│   ├── pr_review/       #   LE workflow principal (revue de PR) — 9 nœuds
│   │   ├── graph.py     #     construction + compilation du StateGraph
│   │   ├── nodes.py     #     la logique de chaque nœud
│   │   ├── edges.py     #     les fonctions de routage conditionnel
│   │   └── state.py     #     le schéma d'état (PRReviewState)
│   ├── ops_assistant/   #   le chat ReAct (graph.py + tools.py = 19 outils)
│   └── (cve_watch, incident_triage, compliance_drift,
│        pipeline_gate, scheduled_audit)   # scaffolds pour extensions futures
│
├── services/            # la « boîte à outils » métier (un fichier = une responsabilité)
│   ├── trivy_service.py, gitleaks_service.py, semgrep_service.py,
│   │   checkov_service.py, osv_service.py     # les 5 scanners
│   ├── diff_parser.py   #   parsing du diff git (machine à états + regex)
│   ├── cache.py         #   Redis (dédup, rate-limit, cache scans)
│   ├── knowledge.py     #   Postgres (historique, profils, scans)
│   ├── git_service.py   #   clone, diff -U15
│   ├── github_api.py    #   poster revue / commentaires / commit status / vérif HMAC
│   ├── slack_api.py     #   notifications + demande d'approbation
│   ├── docker_service.py#   build d'image, lancement de conteneurs scanner
│   ├── artifact_store.py#   écriture des JSON de scan sur disque
│   └── scheduler.py     #   tâches planifiées (disk guard, health digest)
│
├── llm/
│   └── ollama.py        #   getters de modèles : get_fast_llm (7B), get_combined_llm (14B)…
├── models/              # state.py (AgentState), db.py, github_webhooks.py
├── prompts/             # les prompts système (classifier, combined_review…)
├── engine/              # registry des workflows, dispatcher, checkpointer
└── metrics/custom.py    # définition des métriques Prometheus custom
```

**Phrase d'intro à dire** : « L'architecture suit une séparation claire : `routers` = les entrées HTTP, `workflows` = l'orchestration LangGraph, `services` = les briques métier réutilisables, `llm`/`prompts` = la couche IA. Un service = une seule responsabilité, ce qui rend le tout testable. »

---

## 2. Le démarrage (`main.py`)

`main.py` définit l'app FastAPI (`SECURITY AI AGENT`, v0.2.0) et un **`lifespan`** qui, au démarrage :
1. initialise Redis (dégradation gracieuse s'il manque),
2. initialise le **checkpointer Postgres** (persistance du graphe),
3. ouvre le pool de connexions de la knowledge base,
4. vérifie la connectivité **Ollama**,
5. **enregistre tous les workflows** (`register_all_workflows`),
6. lance des **pollers** toutes les 30 s : métriques Ollama (`/api/ps`), LocalAI (`/readyz`), **docker stats** (remplace cAdvisor),
7. démarre le **scheduler** (disk guard + health digest).

Les métriques Prometheus sont exposées sur `GET /metrics` via `prometheus-fastapi-instrumentator`.

---

## 3. Le workflow principal : revue de PR (LangGraph, 9 nœuds)

C'est le cœur de la démo. Le graphe est construit dans `pr_review/graph.py` avec un `StateGraph(PRReviewState)`, compilé avec le checkpointer Postgres et `interrupt_before=["escalate"]` (le point de pause pour l'approbation Slack).

### Schéma du graphe
```
                          intake
                            │
                         classify
            ┌───────────────┼────────────────┬─────────────┐
       (docs)│        (Dockerfile)│      (sinon)│       (erreur)│
        skip_scan         scan_full        scan_fs        error_node
            └───────────────┴────────────────┘                 │
                            │                                    │
                         analyze  ◀── revue combinée 14B          │
                   ┌────────┴─────────┐                          │
        (CRITICAL/HIGH)│          (sinon)│                        │
            escalate (PAUSE Slack)    report ───────────────▶ END ◀┘
                  │                      │
                  └──────────────────────┘
```

### Rôle de chaque nœud (`nodes.py`)

| # | Nœud | Ce qu'il fait |
|---|------|---------------|
| 1 | `intake` | Clone le dépôt (shallow), récupère le diff (`git diff -U15`), liste les fichiers changés, vérifie la présence d'un Dockerfile, charge l'historique du dépôt (10 dernières revues), poste un commentaire « revue en cours ». **Dédup + rate-limit** via Redis ici. |
| 2 | `classify` | Classe la PR en `feature` / `dependency` / `infrastructure` / `docs` / `config` avec le **LLM 7B** (rapide). **Fallback regex** (`_fallback_classify`) si le circuit breaker LLM est ouvert. |
| 3 | `scan_full` | Build Docker + scanners **en parallèle**. Toujours : `trivy_fs` + `gitleaks`. Conditionnels selon la classe (`SCAN_MATRIX`) : semgrep (feature), osv (dependency), checkov (infra). `trivy_image` si le build réussit. |
| 4 | `scan_fs` | Idem mais **sans build Docker** (pas de Dockerfile) → pas de scan d'image. |
| 5 | `skip_scan` | PR purement documentaire → on saute les scans. |
| 6 | `analyze` | **Le cœur IA** : une **seule** requête au **LLM 14B combiné** (`get_combined_llm`) qui produit à la fois la revue sécurité ET la revue qualité de code. Parse le JSON (risk_score, verdict, summary, comments[]), **valide les numéros de ligne** contre le diff réel, poste une **review GitHub inline** avec suggestions. Sauvegarde en knowledge base. |
| 7 | `escalate` | Si risque CRITICAL/HIGH et escalade Slack activée : extrait le top 3 des findings et **poste une demande d'approbation Slack**. Le graphe **se met en pause** ici (`interrupt_before`). |
| 8 | `report` | Poste la synthèse sécurité + qualité sur la PR, fixe le **commit status** (success/failure/error), notifie Slack, **nettoie** (supprime l'image Docker et le clone), enregistre les métriques + la durée. |
| 9 | `error_node` | Gestionnaire d'erreur : commentaire d'échec sur la PR, notif Slack, libération du rate-limit. |

### Le routage conditionnel (`edges.py`)
- **`route_scans`** (après `classify`) : erreur → `error_node` ; docs → `skip_scan` ; Dockerfile présent → `scan_full` ; sinon → `scan_fs`.
- **`route_risk`** (après `analyze`) : erreur → `error_node` ; CRITICAL/HIGH + escalade activée → `escalate` ; sinon → `report`.

### L'état partagé (`state.py` → `PRReviewState`)
Tout transite par un dictionnaire d'état typé. Champs clés : entrées (`pr_number`, `clone_url`, `head_sha`, `pr_title`…), puis remplis par les nœuds (`diff`, `has_dockerfile`, `pr_classification`, `scan_results`, `security_review`, `risk_score`, `verdict`, `code_review_comments`, `repo_history`…). Hérite de `AgentState` (champs communs : `workflow_type`, `task_id`, `messages`…).

---

## 4. La logique « intelligente » à mettre en avant

Ce sont les points qui montrent la **réflexion d'ingénierie**, pas juste « j'appelle un LLM » :

1. **Une seule requête LLM 14B au lieu de deux** (`analyze`) : à l'origine il y avait deux appels (sécurité + qualité). Les fusionner en un seul prompt combiné a divisé le temps par ~2 — décisif en CPU-only. Pipeline ramené à **15–25 min**.

2. **Classification d'abord avec un petit modèle 7B** : inutile de mobiliser le 14B pour décider quels scanners lancer. Le 7B classe vite et oriente la `SCAN_MATRIX` → on ne lance que les scanners pertinents.

3. **Scanners en parallèle** (`asyncio` / sous-processus concurrents) : les 5 scanners ne se bloquent pas l'un l'autre.

4. **Validation anti-hallucination** : chaque commentaire inline proposé par le LLM est **vérifié** — son numéro de ligne doit exister dans le diff réel (`diff_lines_for_file`), sinon il est filtré. Le LLM ne peut pas inventer des lignes.

5. **Fallbacks partout** : circuit breaker LLM (revue dégradée à partir des seuls scans), fallback regex pour la classification, fallback API GitHub si le diff local échoue, parsing markdown si le JSON du LLM est malformé. **Le pipeline ne casse jamais en silence.**

6. **Reprise après pause** : grâce au checkpointer Postgres, l'approbation Slack (`escalate`) peut arriver des heures plus tard — le graphe reprend exactement où il s'était arrêté.

7. **Le diff parser** (`diff_parser.py`) : machine à états + regex sur les en-têtes de hunk `@@ -a,b +c,d @@`, avec un fallback « fuzzy » par nom de fichier. Réécrit lors du Sprint 8 après 3 bugs cumulatifs (PR #14/#15) — c'est l'exemple à donner si elle demande « un problème technique que tu as résolu ».

---

## 5. L'assistant Ops (chat ReAct)

- Endpoint `POST /chat/stream` (SSE), derrière nginx + Basic Auth.
- **Boucle ReAct** : le modèle (par défaut `qwen2.5-coder:7b`) peut appeler jusqu'à **8 outils** avant de répondre. Garde-fou anti-boucle : on bloque un même appel d'outil avec les mêmes arguments.
- **19 outils** (`ops_assistant/tools.py`) répartis en familles :
  - **Hôte** : `vps_status`, `disk_usage`, `top_processes`, `network_stats`, `system_net_io`
  - **Docker** : `list_containers`, `container_logs`, `container_stats`, `inspect_container`, `list_images`, `restart_service`
  - **Ollama** : `ollama_status`
  - **Prometheus** : `query_prometheus`, `query_prometheus_range`, `prometheus_alerts`
  - **Redis** : `redis_info`
  - **Artifacts/DB** : `list_scan_artifacts`, `read_scan_artifact`, `query_database` (SELECT en lecture seule)
- **À dire** : « C'est un agent ReAct : il raisonne, choisit un outil, observe le résultat, recommence. Il peut répondre en langage naturel à "quel conteneur consomme le plus de RAM ?" en interrogeant réellement Docker. »

---

## 6. Configuration (`config.py`) — affectation des modèles

| Tâche | Setting | Modèle |
|---|---|---|
| Classification | `ollama_model_fast` | `qwen2.5-coder:7b` |
| Revue combinée (sécurité + qualité) | `ollama_model_deep` | `qwen2.5-coder:14b` |
| Chat ops | (défaut chat) | `qwen2.5-coder:7b` |

Autres : DSN Postgres, URL Redis, `trivy_severity=CRITICAL,HIGH,MEDIUM`, secrets GitHub/Slack (variables d'env, jamais en dur).
