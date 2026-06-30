# Fiche de pratique — cue cards soutenance

> **But** : ne PAS réciter `SPEECH.md`. Mémoriser pour chaque slide seulement
> **(1) l'amorce** (les 3-4 premiers mots pour démarrer sans blanc),
> **(2) 2-3 ancres** (mots-clés = squelette, l'ordre des idées),
> **(3) le chiffre / la punchline** (la phrase qui doit tomber juste).
> Le slide affiche le reste : tu *relies* les ancres à voix haute, tu n'inventes rien.

---

## Méthode en 4 passes (≈ 1 h par jour, 4 jours)

1. **Passe lecture** — lis `SPEECH.md` à voix haute, lentement, 1 fois. Tu comprends le fil, pas plus.
2. **Passe ancres** — ferme `SPEECH.md`. Ouvre cette fiche. Pour chaque slide, dis le contenu en regardant SEULEMENT les ancres. Tu te trompes sur les mots → normal. Tu dois juste toucher les 3 ancres + le chiffre.
3. **Passe slides** — passe le `.pptx` en mode présentateur. Parle en regardant l'écran, fiche fermée. Si tu cales, regarde l'ancre 2 s, puis repars.
4. **Passe minuteur** — enchaîne tout, chrono en main. Cible **13 min 12 s**. Note les slides où tu dépasses → ce sont eux à re-travailler.

**Règles d'or :**
- Une idée = une respiration. Tu marques un temps d'arrêt entre chaque ancre. Le silence = du contrôle, pas un trou.
- Les **chiffres sont sacrés** : `24 h → 15 min`, `7/7`, `100 % local`, `5 scanners`, `2 modèles (7B/14B)`, `9 nœuds`, `19 outils`, `11 conteneurs`, `8 revues réelles`. Apprends-les comme une table de multiplication.
- Si tu perds le fil : reviens TOUJOURS au refrain → *« rien ne quitte la banque »*. C'est ton filet.

---

## Les 5 refrains (le fil rouge de toute la soutenance)

Si tu ne retiens que 5 phrases, ce sont celles-là — elles reviennent partout :

1. **« Aujourd'hui c'est manuel, jusqu'à 24 h, et ça dépend du relecteur. »** (le problème)
2. **« Un agent, pas un simple appel à un modèle. »** (la thèse)
3. **« 100 % local — aucun code ne quitte la banque. »** (le différenciateur, conformité BCT)
4. **« Le verdict devient un gate technique qui bloque la fusion. »** (la valeur)
5. **« Le système se surveille lui-même. »** (la maturité)

---

## L'ORDRE — les 7 charnières à graver (ta colonne vertébrale)

> Si tu connais ces 7 transitions dans l'ordre, tu ne peux PAS te perdre. Le reste s'improvise depuis les points techniques. Mémorise CECI en priorité.

1. **Intro → Contexte** : « à la BTE, c'est manuel, jusqu'à 24 h »
2. **Problème → Solution** : « notre contribution tient en une phrase… » *(les 3 chiffres)*
3. **Divider 2 — État de l'art** : « passons à l'état de l'art et aux choix technologiques »
4. **Divider 3 — Conception** : « venons-en à la conception » → *un agent, pas un pipeline*
5. **Divider 4 — Réalisation** : « passons à la réalisation » → *la démo*
6. **Démo → Résultats** : « le verdict bloque la fusion → 7/7 »
7. **Divider 5 — Conclusion** : « j'en viens à la conclusion » → « parti d'un VPS vierge… »

**Les 5 chapitres dans l'ordre (ton GPS) :** Contexte → État de l'art → Conception → Réalisation → Conclusion.

---

## Cue cards — 34 slides

> Format : **Amorce** · `ancres` · **CHIFFRE / punchline**

**1. Titre** — *« Monsieur le Président… »* · nom · BTE · 2 encadrants · **« agent IA pour la revue automatisée de code »**

**2. Sommaire** — *« Mon exposé suit le rapport »* · contexte → état de l'art → conception → réalisation → conclusion *(5 parties)*

**3. Introduction** — *« Trois scénarios »* · `injection SQL` · `secret commité` · `image Docker / faille` → **« une faille suffit à compromettre la banque — et aujourd'hui, c'est manuel »** *(le « 24 h » est gardé pour la slide 6)*

**4. Divider 1** — *« Commençons par le contexte. »* *(1 phrase, respire)*

**5. Organisme & existant** — *« Mon stage à la BTE »* · `DCIO · équipe sécurité opérationnelle` *(pas d'histoire de la banque — c'est sur le slide)* · processus à gauche = manuel → **« aucun scanner, aucun gate — tout repose sur l'humain »**

**6. Problématique** — *« Quatre limites »* · `délai 24 h` · `pas de blocage` · `qualité variable (dispo + expertise du relecteur)` · `2 angles morts : secrets + dépendances` → **« l'œil humain n'est pas le bon outil »**

**7. Objectifs (3 clics)** — *« Notre contribution en une phrase »* · agent autonome · OWASP Top 10 · local → **[clic] 24 h→15 min · [clic] 7/7 sans faux positif · [clic] 100 % sur le VPS (BCT)**

**8. Solution proposée** — *« Voici le processus cible »* · `webhook HMAC` · `classifie (~30 s)` · `scanners //` · `LLM local` · `verdict = statut commit` → **« c'est ce statut qui conditionne la fusion, déclenchée par un humain »**

**9. Méthodologie** — *« Scrumban »* · Scrum + Kanban · `10 sprints / 5 mois` · étiquette Expedite → **incident prod sans replanifier**

**10. Divider 2** — *« Passons à l'état de l'art. »*

**11. DevSecOps** — *« Cadre = DevSecOps + shift-left »* · détecter au plus tôt → **« le verdict devient un gate technique »**

**12. Besoins** — *« Six fonctionnels, cinq non fonctionnels »* · F : détecter / revue OWASP / publier+gate / persister / chat / sécuriser · NF : **confidentialité** · performance · résilience · fiabilité · observabilité

**13. Benchmark** — *« Pas la littérature, un banc d'essai sur le matériel cible »* · écartés : `llama3.2:3b` (saturé), `granite` (pas d'outils) · retenus : `7B + 14B à 80 %` → **« Ollama : +22 % vs LocalAI »**

**14. Technologies** — *« Trois briques »* · `5 scanners` (Trivy/Gitleaks/Semgrep/Checkov/OSV) · `2 LLM Ollama` · `LangGraph` (état dans PostgreSQL) → **« −52 % de tokens, le pipeline survit au redémarrage »**

**15. Positionnement** — *« Pourquoi pas un outil du marché ? »* · Snyk/Copilot = cloud (inacceptable) · SonarQube = statique sans explication → **« nous unissons les deux mondes, rien ne sort du VPS »**

**16. Divider 3** — *« Venons-en à la conception. »*

**17. Architecture** — *« 11 conteneurs, 4 couches »* · `nginx` (seul exposé) · `FastAPI+LangGraph+Ollama` · `PostgreSQL+Redis` · observabilité → **« Ollama jamais exposé, réseau interne »**

**18. Manifeste (6 clics)** — *« Ce point fonde le titre : un agent, pas un appel LLM »* · perçoit · raisonne · agit · persiste · `19 outils` · s'auto-exploite → **« il reprend exactement où il s'était arrêté »**

**19. Pipeline (7 clics)** — *« Le cœur : un graphe à 9 nœuds »* · webhook → classify (7B) → route → scan // → analyze (14B) → verdict → publish → **« fusionner les 2 appels du 14B : 35-50 min → 15-25 min »**

**20. Fiabilité** — *« Peut-on faire confiance à un LLM ? Six couches »* · 3 sur le modèle (`temp≈0`, ctx, plafond) · 3 applicatives (garde-outil, anti-hallucination, pas de valeur absente) · parser de lignes → **« aucune erreur de ligne publiée sur GitHub »**

**21. Divider 4** — *« Passons à la réalisation. »*

**22. Environnement** — *« Terrain volontairement contraint »* · `12 cœurs Haswell` · `45 Go` · `sans GPU` · flash attention + cache KV → **« c'est le prix de la confidentialité, et nous l'assumons »**

**23. Défense en profondeur** — *« Chaque scanner = une classe de risque »* · secrets/code/dépendances/IaC/images · le 14B consolide → **« les findings restent déterministes, persistés quoi que dise le modèle »**

**24a. Démo — le code** — *« Une seule PR, dépôt de test »* · `wire_transfer.php` = `7 vulns` + `3 secrets` · requirements obsolète · Dockerfile root → **« le terrain de jeu idéal »**

**24b. Démo — l'agent travaille** — *« Le dev pousse, et n'a plus rien à faire »* · logs en direct · `7B classe` · `6 scanners //` · **Semgrep 43 · OSV 111 · Trivy 64** → **« tout en local »**

**24c. Démo — verdict inline** — *« Publié sur la PR »* · synthèse `CRITIQUE` · `8 commentaires inline` ancrés ligne par ligne · **[clic] statut rouge = fusion bloquée + Slack** → **« il a arrêté le code à la porte »**

**25. Bénéfices** — *« Du manuel à l'agent »* · délai ÷100 · OWASP systématique · gate effectif · traçabilité · **7/7 + 8 revues réelles persistées**

**26a. Observabilité — la stack** — *« L'agent voit tout le VPS »* · **28 métriques · 15 alertes · 3 dashboards** · refresh 30 s · socket Docker (cAdvisor KO)

**26b. Observabilité — ça agit** — *« Pas décoratif, ça agit »* · alerte réelle `CPU 99 %` → Slack · `✅ Resolved` auto · verdict PR dans le même canal → **« la boucle observation → alerte → action est bouclée »**

**27. Chat & autonomie** — *« 19 outils, langage naturel, sans SQL »* · cite la valeur mesurée (jamais inventée) · s'auto-exploite : gardien disque / digest 09:00 → **« la réponse est mesurée, pas inventée »**

**28. Tests** — *« Les mécanismes critiques »* · signature rejetée · webhook dupliqué ignoré · circuit breaker (repli) · gardien disque → **« 14 vérifications de bout en bout, toutes validées »**

**29. Divider 5** — *« J'en viens à la conclusion. »*

**30. Limites & perspectives** — *« Deux limites assumées, un point de vigilance »* · CPU = `15-25 min` · corpus restreint · diff = entrée non fiable → **3 perspectives : GPU (~3000 €, 2-5 min) · passage à l'échelle · dashboard risque RSSI**

**31. Conclusion** — *« Parti d'un VPS vierge »* · agent complet, déployé en prod, remis à la BTE → **« socle de sa transformation DevSecOps. Je vous remercie. »**

---

## Plan B — si tu as un trou total (3 secondes de panique)

1. **Regarde le titre du slide** → il te donne le sujet.
2. **Dis le refrain le plus proche** (voir les 5 refrains) → ça meuble et c'est juste.
3. **Lis une donnée chiffrée à l'écran** → « comme vous le voyez ici, 7 vulnérabilités sur 7 » → tu es reparti.

Le jury ne voit pas tes notes. Une demi-seconde de silence pour toi = une respiration normale pour eux. **Ralentis : tu parles toujours trop vite à l'oral.**
