# 05 — Questions anticipées et réponses

> Les questions qu'une reviewer technique pose typiquement, et une réponse solide et honnête pour chacune. Relire la veille.

---

## Architecture & conteneurs

**Q : Je vois 12 conteneurs, pas 11 ?**
R : Le système cœur, c'est 11 conteneurs. Le 12ᵉ, `localai`, est une sandbox optionnelle que j'ai ajoutée au Post-Sprint 8 pour benchmarker un second moteur d'inférence contre Ollama (résultat : Ollama ~+22 % de débit, donc il reste le backend de production). Elle est non critique — ses alertes sont en sévérité `info`.

**Q : Pourquoi Docker Compose et pas Kubernetes ?**
R : Une seule machine (VPS), une dizaine de conteneurs, pas de besoin de scaling horizontal multi-nœuds. Compose donne la reproductibilité et l'isolation nécessaires sans la complexité opérationnelle de Kubernetes. Si la BTE voulait industrialiser sur plusieurs nœuds, la migration vers K8s serait l'étape suivante.

**Q : Comment les conteneurs communiquent-ils ?**
R : Tous sur un réseau bridge privé Docker `devsecops-net` (`172.20.0.0/16`), par nom de service (DNS interne Docker). Seul `node-exporter` est en `network_mode: host` pour mesurer la vraie machine.

**Q : Qu'est-ce qui est exposé à l'extérieur ?**
R : Uniquement nginx (80/443). Il sert de reverse proxy et porte l'authentification HTTP Basic sur l'UI et l'API de chat. La stack interne n'est pas joignable directement de l'extérieur ; elle communique sur le réseau privé Docker.

**Q : Comment sécurises-tu l'accès ?**
R : Plusieurs couches — webhooks GitHub signés et vérifiés en **HMAC-SHA256** ; UI/chat derrière **HTTP Basic Auth** via nginx ; secrets (tokens GitHub/Slack, mots de passe DB) en variables d'environnement, jamais en dur dans le code ; réseau interne isolé.

---

## L'IA / les LLM

**Q : Pourquoi des modèles locaux et pas GPT-4 / Claude ?**
R : Souveraineté des données. Le code de la banque ne doit pas sortir vers un cloud externe. Ollama héberge les modèles **on-premise**. C'est non négociable dans un contexte bancaire.

**Q : Pourquoi qwen2.5-coder et ces tailles (7B / 14B) ?**
R : qwen2.5-coder est spécialisé code, performant sur le raisonnement sécurité. Le **7B** classe vite (rapide, suffisant pour décider quels scanners lancer) ; le **14B** fait la revue de fond. Tout est contraint par le **CPU-only** : un modèle plus gros serait trop lent. C'est l'arbitrage qualité/latence du projet.

**Q : Le LLM peut halluciner. Comment tu te protèges ?**
R : Plusieurs garde-fous. Le principal : chaque commentaire inline proposé par le LLM est **validé** — son numéro de ligne doit exister dans le diff réel, sinon il est rejeté. Le LLM ne peut pas commenter une ligne qui n'existe pas. Plus : prompts contraints, parsing JSON strict avec fallback, et le LLM s'appuie sur les findings **factuels** des scanners (Trivy, Semgrep…), pas seulement sur son intuition.

**Q : Pourquoi un seul appel LLM combiné au lieu de deux ?**
R : À l'origine, deux appels 14B (un sécurité, un qualité). Les fusionner en un prompt combiné a ~divisé le temps par deux — décisif en CPU-only. Le pipeline est passé à 15–25 min.

---

## LangGraph / le workflow

**Q : Pourquoi LangGraph ?**
R : Un pipeline de revue est une **machine à états** avec des branches conditionnelles (docs → skip, Dockerfile → build, risque élevé → escalade). LangGraph modélise ça nativement en graphe, avec un **checkpointer** qui persiste l'état → on peut **mettre en pause** (approbation Slack) et **reprendre**. Plus propre qu'un enchaînement de fonctions ad hoc.

**Q : Que se passe-t-il si l'agent crashe au milieu d'une revue ?**
R : L'état du graphe est persisté dans Postgres (checkpointer). Au redémarrage, le workflow peut reprendre. Et chaque nœud a un chemin d'erreur (`error_node`) qui poste un commentaire d'échec et libère le rate-limit.

**Q : Comment décides-tu quels scanners lancer ?**
R : Le nœud `classify` (7B) catégorise la PR, puis une `SCAN_MATRIX` choisit : Trivy + Gitleaks toujours ; Semgrep si feature ; OSV si dépendances ; Checkov si infra ; Trivy image si build Docker réussi. On ne gaspille pas de CPU sur des scanners inutiles.

---

## Les scanners (DevSecOps)

**Q : Que fait chaque scanner ?**
R :
- **Trivy** — vulnérabilités des images et du filesystem (CVE des paquets).
- **Gitleaks** — secrets/credentials en dur dans le code et l'historique git.
- **Semgrep** — patterns de code vulnérables (configs `p/security-audit`, `p/owasp-top-ten`).
- **Checkov** — mauvaises configurations IaC (Terraform, K8s, Dockerfile…).
- **OSV-Scanner** — vulnérabilités des dépendances via les lockfiles.

**Q : Ils tournent en série ?**
R : Non, **en parallèle** (sous-processus asyncio concurrents), donc le temps total ≈ celui du scanner le plus lent, pas la somme.

**Q : Pourquoi mapper sur l'OWASP Top 10 ?**
R : C'est le référentiel reconnu de l'industrie ; Semgrep a un ruleset dédié. Ça rend les findings parlants pour n'importe quel auditeur sécurité.

---

## Observabilité

**Q : Pourquoi Prometheus ET VictoriaMetrics ?**
R : Prometheus = temps réel + règles d'alerte, 30 j de rétention locale. VictoriaMetrics = archive long terme (90 j), compact et performant, alimenté par `remote_write`. Grafana lit les deux.

**Q : Pourquoi pas cAdvisor pour les métriques conteneurs ?**
R : Docker sur cet hôte utilise le containerd snapshotter, incompatible avec cAdvisor. J'ai écrit un poller maison dans l'agent qui lit `docker stats` toutes les 30 s et expose des gauges `container_*`. Changement d'approche assumé (Sprint 6).

**Q : Comment l'agent se surveille-t-il lui-même ?**
R : Il expose ses propres métriques métier sur `/metrics` (revues par risque, durée pipeline, durée scanners, erreurs, cache). Prometheus les scrape. 15 règles d'alerte couvrent l'hôte, l'agent et Ollama.

---

## Autonomie & fiabilité

**Q : Montre-moi quelque chose d'autonome.**
R : L'auto-remédiation disque. Disque saturé → Prometheus `DiskCritical` → AlertManager → l'agent reçoit le webhook et lance `docker builder prune -f` tout seul, plus une alerte Slack. Né d'un vrai incident disque en avril 2026. Un scheduler vérifie aussi le disque toutes les 30 min et envoie un digest santé quotidien sur Slack.

**Q : Quel a été le problème technique le plus dur ?**
R : La réécriture du **diff parser** (Sprint 8). Trois bugs cumulatifs sur les PR #14/#15 faisaient échouer le placement des commentaires inline. Je l'ai réécrit en machine à états + regex tolérant sur les en-têtes de hunk, avec un fallback par nom de fichier. C'est ce qui garantit que les commentaires tombent sur les bonnes lignes.

---

## Limites & perspectives (montrer du recul)

**Q : Quelles sont les limites ?**
R : La latence — 15–25 min par PR en CPU-only. Sur GPU, ce serait quelques minutes : c'est l'évolution la plus rentable. Le périmètre est la revue de PR ; les autres workflows (cve_watch, incident_triage, compliance_drift…) sont des scaffolds prévus pour des extensions futures.

**Q : Et si tu avais plus de temps / un budget GPU ?**
R : Migration GPU (gain de latence majeur), activation des workflows planifiés (audit périodique, veille CVE), et fine-tuning d'un modèle sur l'historique des revues stocké en base.

**Q : Est-ce en production à la BTE ?**
R : C'est un prototype fonctionnel déployé sur VPS, validé sur des PR réelles. L'industrialisation (intégration au SI bancaire, GPU, durcissement complet) serait la phase suivante côté DCIO.
