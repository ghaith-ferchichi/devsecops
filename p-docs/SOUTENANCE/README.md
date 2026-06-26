# Kit de préparation — Soutenance technique
### BTE Security AI Agent — Ghaith FERCHICHI

Ce dossier contient tout le nécessaire pour préparer la réunion technique en ligne avec l'encadrante (Mme Ghayet El Mouna ZHIOUA), qui veut **voir dans le système réel ce qui est écrit dans le rapport**.

---

## Comment utiliser ce kit

| Fichier | Quand l'utiliser | Contenu |
|---|---|---|
| **`00_SCENARIO_DEMO.md`** | À lire en **premier** ; c'est le fil de la réunion | Le playbook en 6 actes (big picture → détail), conseils de pilotage, checklist 30 min avant |
| **`01_VPS_ET_CONTENEURS.md`** | Acte 2 (architecture) | Le VPS, les 11 conteneurs un par un, les ports, **les flux de communication** |
| **`02_CODE_AGENT.md`** | Acte 3 (le code) | Arborescence du code, le workflow LangGraph en 9 nœuds, la logique d'ingénierie |
| **`03_OBSERVABILITE.md`** | Acte 5 (monitoring) | Prometheus / VictoriaMetrics / Grafana / AlertManager / node-exporter, les 15 alertes, la boucle autonome |
| **`04_COMMANDES_LIVE.md`** | **Pendant** la démo, ouvert en permanence | Toutes les commandes à copier-coller, dans l'ordre, avec ce qu'il faut dire |
| **`05_QUESTIONS_REPONSES.md`** | La veille + filet pendant les questions | ~30 questions anticipées avec réponses solides et honnêtes |
| **`06_DEMO_PR_LIVE.md`** | Acte 4 (le moment clé) | Le scénario d'une **vraie revue de PR** de bout en bout : commande → explication → sortie réelle → ce que ça prouve (testé sur PR #19) |

---

## Le message en une phrase
> « Un agent IA **autonome**, **auto-hébergé** sur un VPS, qui review automatiquement la sécurité et la qualité de chaque Pull Request de la BTE et publie son verdict sur GitHub — sans jamais envoyer le code de la banque vers un cloud externe. »

## Les 3 idées à faire passer absolument
1. **Souveraineté** — LLM 100 % local (Ollama), aucune fuite de code vers un tiers.
2. **Autonomie** — l'agent observe, alerte et s'auto-répare (boucle disque Prometheus→AlertManager→agent).
3. **Ingénierie réfléchie** — pas juste « j'appelle un LLM » : classification 7B avant 14B, fusion des appels, scanners en parallèle, validation anti-hallucination, fallbacks partout, reprise sur checkpoint.

---

## Règles d'or pour la réunion
- **Tu pilotes le fil** : annonce chaque étape avant de l'exécuter.
- **Chaque ligne du rapport = une preuve live** (une commande, une table, un dashboard).
- **Ne jamais improviser une commande** : tout est dans `04_COMMANDES_LIVE.md`, testé avant.
- **Ne jamais inventer une réponse** : si tu ne sais pas, dis comment tu l'aborderais.
- **Filet de sécurité** : des captures d'écran de chaque sortie attendue, au cas où le live planterait.
- Le pipeline complet d'une PR dure **15–25 min** (CPU-only) : lance une PR en début de séance, ou montre une PR déjà traitée.
