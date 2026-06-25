# 04 — Commandes pour la démo live sur le VPS

> **Règle d'or** : ne jamais improviser une commande devant l'écran partagé. Tout est ici, prêt à copier-coller, dans l'ordre. Chaque bloc indique **ce que tu dis** pendant que ça s'exécute.
>
> Avant la réunion : `cd /opt/devsecops` et teste **chaque** commande une fois pour vérifier qu'elle passe.

---

## 0. Préparation (avant de partager l'écran)
```bash
cd /opt/devsecops
clear
```
- Agrandir la police du terminal.
- Avoir ce fichier ouvert sur un 2ᵉ écran / téléphone.
- Avoir l'onglet GitHub (un PR de démo) et Grafana prêts dans le navigateur.

### 0.bis ⚠️ RÉCHAUFFER LE MODÈLE (étape critique — à faire juste avant)
Au repos, Ollama décharge le modèle de la RAM (`KEEP_ALIVE=20m`). Sans réchauffement, le **premier** appel LLM en démo est lent (cold-load) et l'alerte `OllamaNoModelLoaded` s'affiche. On réchauffe :
```bash
docker exec ollama ollama run qwen2.5-coder:7b "Réponds juste: OK"
docker exec ollama ollama ps        # doit montrer le modèle chargé, "100% CPU"
```
Effet : le modèle reste chaud ~20 min, et l'alerte d'inactivité disparaît. **À relancer si la réunion traîne avant la partie chat/revue.**

---

## 1. Vue d'ensemble : tous les conteneurs
```bash
docker compose ps
```
**Tu dis** : « Voici les 11 conteneurs du système. On a la couche applicative — `agent`, `ollama` — la couche données — `postgres`, `redis` — l'observabilité — `prometheus`, `victoriametrics`, `grafana`, `alertmanager`, `node-exporter` — et `nginx` qui est le point d'entrée. Tous sont `healthy`. »

Variante plus lisible (état + santé) :
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## 2. Le réseau interne entre conteneurs
```bash
docker network inspect devsecops-net --format '{{range .Containers}}{{.Name}} → {{.IPv4Address}}{{println}}{{end}}'
```
**Tu dis** : « Tous les conteneurs sont sur le même réseau bridge privé `devsecops-net`. Ils se parlent par leur nom de service, pas par IP. `node-exporter` est le seul à part car il tourne en mode host pour voir la vraie machine. »

---

## 3. PostgreSQL — la mémoire long terme

Entrer dans la base :
```bash
docker exec -it postgres psql -U devsecops -d devsecops_db
```
Puis, dans le prompt `psql` :
```sql
-- Lister les tables
\dt

-- L'historique des revues de PR
SELECT pr_number, classification, risk_score, verdict, duration_ms
FROM pr_reviews ORDER BY created_at DESC LIMIT 10;

-- Les profils de dépôts (mémoire accumulée)
SELECT repo_full_name, total_reviews, risk_score_avg, has_dockerfile FROM repo_profiles;

-- Les politiques de sécurité par défaut
SELECT policy_name, policy_type, config FROM security_policies;

-- Quitter
\q
```
**Tu dis** : « Postgres stocke l'historique de chaque revue, des profils de dépôts qui s'enrichissent au fil du temps, et les politiques de sécurité. Il sert aussi de checkpointer LangGraph : c'est ce qui permet de mettre un workflow en pause pour une approbation Slack et de le reprendre plus tard. »

> **`\dt` affiche 10 tables.** 6 sont métier (`pr_reviews`, `scan_results`, `repo_profiles`, `sbom_cache`, `security_policies`, `incidents`) ; les 4 autres (`checkpoints`, `checkpoint_blobs`, `checkpoint_writes`, `checkpoint_migrations`) sont créées automatiquement par le **checkpointer LangGraph** — c'est là qu'est persisté l'état des graphes. Si elle demande : « ces 4 tables `checkpoint_*`, c'est LangGraph qui les gère pour la reprise des workflows en pause. »

---

## 4. Redis — le cache / garde-fou
```bash
# Infos générales
docker exec -it redis redis-cli INFO server | head -15

# Voir les clés actuelles (dédup, rate-limit, cache de scans)
docker exec -it redis redis-cli KEYS '*'

# Stats mémoire + hit rate
docker exec -it redis redis-cli INFO stats | grep keyspace
```
**Tu dis** : « Redis fait trois choses : la déduplication des webhooks (on ne traite pas deux fois la même PR), le rate-limiting (max 3 PR concurrentes par dépôt pour protéger le CPU), et le cache des résultats de scan avec un TTL d'une heure. »

---

## 5. Ollama — le serveur d'inférence
```bash
# Modèles installés
docker exec -it ollama ollama list

# Modèle actuellement chargé en RAM
docker exec -it ollama ollama ps
```
**Tu dis** : « On utilise qwen2.5-coder en 7B pour la classification rapide et le chat, et en 14B pour la revue combinée. Tout est CPU-only, d'où le tuning : Flash Attention, cache KV quantifié 8 bits, les 12 cœurs épinglés. »

---

## 6. Le code de l'agent — la structure
```bash
# L'arborescence du code
find agent/app -name '*.py' | sort | head -50

# Le workflow principal : le graphe en 9 nœuds
cat agent/app/workflows/pr_review/graph.py

# La logique de chaque nœud
 less agent/app/workflows/pr_review/nodes.py     # q pour quitter

# Le routage conditionnel
cat agent/app/workflows/pr_review/edges.py

# Les 19 outils du chat ReAct
grep -E 'name="|def ' agent/app/workflows/ops_assistant/tools.py | head -40
```
**Tu dis** : (suivre le plan de `02_CODE_AGENT.md`) « Le graphe a 9 nœuds : intake → classify → scan → analyze → escalate/report. Le routage est conditionnel : une PR docs saute les scans, une PR avec Dockerfile passe par un build complet… »

---

## 7. L'agent en fonctionnement — santé et logs
```bash
# Health check
curl -s http://localhost:8000/health

# Les logs de l'agent en direct (Ctrl+C pour arrêter)
docker logs devsecops-agent --tail 40

# Les métriques custom exposées à Prometheus
curl -s http://localhost:8000/metrics | grep -E '^agent_|^container_|^ollama_' | head -30
```
**Tu dis** : « L'agent expose ses propres métriques métier : nombre de revues par niveau de risque, durée du pipeline, temps de chaque scanner, hit rate du cache… c'est ce que Prometheus scrape toutes les 15 s. »

---

## 8. L'observabilité — Prometheus, alertes, VictoriaMetrics
```bash
# Les cibles scrappées par Prometheus (toutes "up")
curl -s http://localhost:9090/prometheus/api/v1/targets | python3 -m json.tool | grep -E '"job"|"health"'

# Les règles d'alerte chargées
curl -s http://localhost:9090/prometheus/api/v1/rules | python3 -m json.tool | grep '"name"'

# Une requête métier en PromQL : nb de revues par verdict
curl -s 'http://localhost:9090/prometheus/api/v1/query?query=agent_reviews_total' | python3 -m json.tool
```
**Tu dis** : « Prometheus scrape l'agent, node-exporter, alertmanager. Il évalue 15 règles d'alerte et pousse tout vers VictoriaMetrics en remote_write pour 90 jours de rétention. Grafana lit les deux. »

Puis basculer sur le **navigateur** → Grafana (`/grafana/`) → montrer les 3 dashboards en live.

---

## 9. La boucle autonome — auto-remédiation disque
```bash
# L'état disque vu par l'agent
curl -s http://localhost:8000/metrics | grep agent_disk

# La règle d'alerte disque
grep -A6 'DiskCritical' prometheus/alerts.rules.yml

# Le code de l'auto-remédiation (webhook alertmanager → prune)
grep -n -A12 'alertmanager' agent/app/routers/webhooks.py | head -40
```
**Tu dis** : « Quand le disque sature, node-exporter le mesure, Prometheus déclenche DiskCritical, AlertManager prévient Slack ET appelle l'agent, qui lance `docker builder prune` tout seul. C'est né d'un vrai incident disque en avril. »

---

## 10. Le scénario star : déclencher une vraie revue de PR

Le plus marquant : **ouvrir une PR de démo** sur GitHub pendant la réunion, puis :
```bash
# Suivre le pipeline en direct dans les logs
docker logs devsecops-agent -f
```
**Tu dis** (en montrant les étapes défiler) : « Le webhook arrive, signature HMAC vérifiée → intake clone et fait le diff → classify avec le 7B → les scanners tournent en parallèle → la revue 14B → publication sur GitHub. » Puis aller sur la PR GitHub montrer **les commentaires inline** publiés par l'agent.

> ⚠️ Le pipeline complet dure **15–25 min** (CPU-only). Pour la réunion : soit lancer la PR **en début** de séance et y revenir à la fin, soit montrer une **PR déjà traitée** (commentaires + commit status déjà visibles sur GitHub, et la ligne correspondante dans `pr_reviews`).

---

## 10.bis Le chat ops en live (assistant ReAct) — testé ✅
Le plus simple : ouvrir l'**UI de chat** dans le navigateur (`/ui`, Basic Auth) et poser la question à l'oral. Sinon, en terminal :
```bash
curl -s --no-buffer -X POST http://localhost:8000/chat/stream \
  -H 'Content-Type: application/json' \
  -d '{"message":"Quel conteneur consomme le plus de RAM ? Réponds en une phrase.","model":"qwen2.5-coder:7b","history":[]}'
```
**✅ Questions PROUVÉES fidèles** (testées end-to-end : bon outil + réponse correcte sans hallucination) — **n'utilise QUE celles-ci en démo** :
- « **Quel conteneur consomme le plus de RAM ?** » → outil `container_stats` → réponse correcte vérifiée (« localai 94.56 % »)
- « **Combien de revues de Pull Request y a-t-il en base, et quels sont les verdicts ?** » → outil `query_database` → renvoie les vraies lignes (5 REQUEST_CHANGES + 3 BLOCK). **C'est LA question pour prouver l'accès réel à PostgreSQL.**

**Tu dis** : « C'est un agent ReAct : il raisonne, choisit un outil — ici `query_database` —, écrit une vraie requête SQL, interroge PostgreSQL, puis répond en langage naturel à partir des données réelles. »

> ⚠️ **À ÉVITER en démo avec le 7B : les questions LARGES** (« quel est l'état du VPS ? », « tout va bien ? »). Le 7B sélectionne le bon outil mais sa **synthèse finale peut halluciner** des chiffres pour remplir un tableau (constaté au test). Pour montrer l'état global du VPS, **utilise plutôt les commandes terminal directes** (§7, §8) — c'est plus fiable et plus parlant qu'une réponse de chat.
>
> ⚠️ **Pré-requis** : modèle **réchauffé** (§0.bis), sinon > 1 min de cold-load. Une **seule** question à la fois (CPU-only, ~30-90 s). Garde une question de secours simple.

---

## 11. Filet de sécurité — si une commande échoue
- `docker compose ps` pour vérifier qu'un conteneur n'est pas tombé.
- `docker compose restart <service>` pour relancer proprement.
- Ne pas paniquer : passer au point suivant et dire « j'y reviens ». Avoir des **captures d'écran** de chaque sortie attendue en secours.
