# 00 — Le scénario de la réunion (playbook)

> La narration, du **big picture** au **détail**. Suivre cet ordre : il raconte une histoire logique et garde le contrôle de la réunion. Durée cible ~30–40 min hors questions.

---

## Principe directeur
La reviewer veut **voir dans le système réel ce qui est écrit dans le rapport**. La stratégie gagnante :
1. **Toujours partir du pourquoi (besoin métier), puis le comment (technique), puis le montrer (live).**
2. **Tu pilotes le fil.** Tu annonces chaque étape avant de l'exécuter → elle te suit au lieu de te tester à froid.
3. **Chaque affirmation du rapport = une preuve live.** « Le rapport dit 11 conteneurs » → `docker compose ps`. « Une mémoire des revues » → `SELECT … FROM pr_reviews`.

---

## Déroulé en 6 actes

### Acte 1 — Le problème et la solution (3–4 min, sans écran technique)
**Dire** : « À la BTE, la revue de sécurité du code était manuelle, lente et dépendante de la disponibilité d'un expert. Mon projet : un agent IA autonome qui review automatiquement chaque Pull Request — sécurité ET qualité — et publie son verdict directement sur GitHub, le tout auto-hébergé sur un VPS, sans envoyer le code de la banque vers un cloud externe. »

Points à poser :
- **Souveraineté des données** : LLM local (Ollama), rien ne sort vers OpenAI/Anthropic.
- **Autonomie** : l'agent se surveille, s'auto-répare (disque), alerte sur Slack.
- **Méthodologie** : Scrumban, 10 sprints de 2 semaines, 6 jalons (M1→M6), du 2 février au 30 juin 2026.

### Acte 2 — L'architecture globale (5 min) → `01_VPS_ET_CONTENEURS.md`
- Montrer le **schéma en 4 couches** (exposition / applicative / données / observabilité).
- `docker compose ps` → « voici les 11 conteneurs cœur ; le 12ᵉ visible, `localai`, est une sandbox optionnelle d'évaluation ».
- Donner la **phrase de synthèse** : « L'agent est au centre : Ollama pour l'IA, Postgres+Redis pour la mémoire, Docker pour les scanners, GitHub/Slack vers l'extérieur ; Prometheus observe, VictoriaMetrics archive, Grafana affiche, AlertManager réagit. »

### Acte 3 — Le flux d'une revue de PR (8–10 min) → `02_CODE_AGENT.md`
C'est le cœur. Raconter le **parcours d'une PR** à travers les 9 nœuds :
`intake → classify (7B) → scan (5 scanners //) → analyze (14B combiné) → escalate? → report`.
- Ouvrir `graph.py` (le graphe), puis `nodes.py` (la logique), puis `edges.py` (le routage).
- Insister sur les **décisions d'ingénierie** (section 4 de `02_CODE_AGENT.md`) : fusion des 2 appels LLM en 1, classification 7B avant 14B, scanners en parallèle, **validation anti-hallucination** des numéros de ligne, fallbacks partout, reprise après pause via checkpointer.

### Acte 4 — Données vivantes (5 min) → `04_COMMANDES_LIVE.md` §3-§5
- **Postgres** : `\dt` puis `SELECT … FROM pr_reviews` → « la mémoire des revues ».
- **Redis** : `KEYS *` → « dédup, rate-limit, cache ».
- **Ollama** : `ollama list` / `ollama ps` → « les modèles, CPU-only ».

### Acte 5 — Observabilité et autonomie (5–7 min) → `03_OBSERVABILITE.md`
- La chaîne : node-exporter + agent → Prometheus → VictoriaMetrics / AlertManager → Grafana / Slack.
- Répondre d'avance à « pourquoi 2 bases de métriques » (30j temps réel vs 90j archive).
- Raconter la **boucle d'auto-remédiation disque** (le scénario star de l'autonomie).
- Montrer Grafana en live (3 dashboards).

### Acte 6 — Démonstration finale (5 min) → `04_COMMANDES_LIVE.md` §10
- Idéalement : une PR déjà traitée → montrer **les commentaires inline sur GitHub** + le **commit status** + la ligne dans `pr_reviews`.
- Ou lancer une PR en direct au début de la réunion et y revenir ici.
- Clore avec le **chat ops** : poser une vraie question (« quel conteneur consomme le plus de RAM ? ») et montrer l'agent ReAct interroger Docker en live.

---

## Conseils de pilotage
- **Garde le terminal préparé** (`04_COMMANDES_LIVE.md`), police agrandie, dossier `cd /opt/devsecops`.
- **Si une question arrive trop tôt** : « excellente question, j'y arrive juste après dans la partie X » → tu gardes le fil.
- **Si tu ne sais pas** : ne jamais inventer. « C'est un point que je n'ai pas instrumenté / hors périmètre du stage ; voici comment je l'aborderais. »
- **Vocabulaire** : reste précis (HMAC-SHA256, StateGraph, remote_write, checkpointer). La précision = la crédibilité.
- **Le filet** : captures d'écran de chaque sortie attendue, au cas où le live planterait.

---

## Checklist 30 min avant
- [ ] `docker compose ps` → tous `healthy`
- [ ] `curl localhost:8000/health` → OK
- [ ] **Réchauffer le modèle** (§0.bis de `04`) → `ollama ps` montre le modèle chargé ; plus d'alerte `OllamaNoModelLoaded`
- [ ] Grafana s'ouvre, les 3 dashboards affichent des données
- [ ] Une PR de démo prête sur GitHub (ou une déjà traitée identifiée)
- [ ] Terminal : police agrandie, `cd /opt/devsecops`, `clear`
- [ ] Les 5 fichiers de ce dossier ouverts sur un 2ᵉ écran
- [ ] `05_QUESTIONS_REPONSES.md` relu une fois
