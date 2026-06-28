# Discours de soutenance — BTE Security AI Agent

> Script aligné sur le deck généré (`build_pptx_modern.py`). Miroir exact des notes du présentateur intégrées dans le `.pptx`.

**35 diapositives · durée cible : 13 min 53 s.**


## Minutage

| # | Diapositive | Durée |
|---|---|---|
| 1 | Titre | ≈ 30 s |
| 2 | Sommaire | ≈ 10 s |
| 3 | Introduction | ≈ 35 s |
| 4 | Divider 1 | ≈ 5 s |
| 5 | Organisme & AS-IS | ≈ 24 s |
| 6 | Problématique | ≈ 30 s |
| 7 | Objectifs et contribution (builds : 3 clics) | ≈ 40 s |
| 8 | Solution TO-BE | ≈ 30 s |
| 9 | Méthodologie | ≈ 20 s |
| 10 | Divider 2 | ≈ 5 s |
| 11 | DevSecOps | ≈ 18 s |
| 12 | Besoins | ≈ 18 s |
| 13 | Benchmark | ≈ 32 s |
| 14 | Technologies retenues | ≈ 30 s |
| 15 | Positionnement | ≈ 22 s |
| 16 | Divider 3 | ≈ 5 s |
| 17 | Architecture | ≈ 25 s |
| 18 | Manifeste (builds : 6 clics) | ≈ 35 s |
| 19 | Pipeline (builds : 7 clics) | ≈ 42 s |
| 20 | Fiabilité | ≈ 35 s |
| 21 | Divider 4 | ≈ 5 s |
| 22 | Environnement | ≈ 20 s |
| 23 | Défense en profondeur | ≈ 30 s |
| 24a | Démonstration 1/3 : le code soumis | ≈ 25 s |
| 24b | Démonstration 2/3 : l'agent au travail | ≈ 30 s |
| 24c | Démonstration 3/3 : verdict et revue inline | ≈ 30 s |
| 25 | Bénéfices & résultats | ≈ 25 s |
| 26a | Observabilité 1/2 : la stack | ≈ 18 s |
| 26b | Observabilité 2/2 : pannes détectées | ≈ 17 s |
| 27 | Chat & autonomie | ≈ 25 s |
| 28 | Phi-4 | ≈ 22 s |
| 29 | Tests et validation | ≈ 20 s |
| 30 | Divider 5 | ≈ 5 s |
| 31 | Limites assumées & perspectives | ≈ 40 s |
| 32 | Conclusion | ≈ 30 s |
| | **Total** | **13 min 53 s** |

## Discours

### 1. Titre — ≈ 30 s

Monsieur le Président du jury, Madame, Messieurs les membres du jury, bonjour. Je m'appelle Ghaith Ferchichi et j'ai l'honneur de vous présenter mon projet de fin d'études, réalisé au sein de la Banque de Tunisie et des Émirats, sous l'encadrement de Monsieur Kamel Kaouech, côté banque, et de Madame Ghayet El Mouna Zhioua, côté ISI. Il s'intitule BTE Security AI Agent : un agent d'intelligence artificielle pour la revue automatisée de code.

### 2. Sommaire — ≈ 10 s

Mon exposé suit la structure du rapport : le contexte général, l'état de l'art et les choix technologiques, la conception de l'agent, sa réalisation et ses résultats, puis la conclusion et les perspectives.

### 3. Introduction — ≈ 35 s

Partons de trois scénarios concrets : une injection SQL fusionnée dans une API de paiement, un secret d'authentification commité par mégarde dans un dépôt, une image Docker bâtie sur une bibliothèque exposée à un CVE critique. Chacune de ces failles peut compromettre le système d'information de la banque. Or, à la BTE, la revue de sécurité du code est entièrement manuelle : elle peut atteindre vingt-quatre heures, et sa qualité dépend de la disponibilité et de l'expertise du relecteur du jour. C'est ce constat qui motive ce travail.

### 4. Divider 1 — ≈ 5 s

Commençons par le contexte général.

### 5. Organisme & AS-IS — ≈ 24 s

La BTE est née en 1982 d'une convention entre l'État tunisien et l'Abu Dhabi Investment Authority. Mon stage s'est déroulé à la Direction Centrale de l'Informatique et de l'Organisation, en sécurité opérationnelle. Le processus existant, à gauche : à chaque Pull Request, un relecteur examine le diff à la main, commente, puis fusionne. Aucun scanner, aucun gate de pipeline — tout repose sur l'humain.

### 6. Problématique — ≈ 30 s

Quatre limites en découlent. Le délai, d'abord : jusqu'à vingt-quatre heures, pendant lesquelles la vulnérabilité reste exposée. L'absence de blocage technique, ensuite : une Pull Request porteuse d'une faille critique peut être fusionnée sans obstacle. Une qualité de revue qui varie d'un relecteur à l'autre. Et deux angles morts structurels : les secrets commités par accident et les dépendances vulnérables, deux catégories pour lesquelles l'œil humain n'est pas le bon outil.

### 7. Objectifs et contribution (builds : 3 clics) — ≈ 40 s

Notre contribution tient en une phrase : un agent d'intelligence artificielle autonome qui revoit chaque Pull Request selon la grille OWASP Top 10, publie ses correctifs directement sur GitHub, et s'exécute intégralement en local — aucun code ne quitte la banque. Trois chiffres résument le résultat. [clic] Le délai de revue passe de vingt-quatre heures à une quinzaine de minutes. [clic] Sur la validation contrôlée, sept vulnérabilités sur sept sont détectées, sans faux positif dans le fichier modifié. [clic] Et cent pour cent de l'inférence reste sur le VPS de la banque, conformément aux exigences de la Banque Centrale de Tunisie.

### 8. Solution TO-BE — ≈ 30 s

Voici le processus cible. GitHub émet un webhook signé HMAC-SHA256 ; l'agent vérifie la signature, élimine les doublons, classifie la Pull Request en une trentaine de secondes, exécute en parallèle les scanners pertinents, puis consolide leurs résultats avec un modèle de langage local. Il publie sur GitHub la revue complète : score de risque, commentaires ligne par ligne et verdict — APPROVE, REQUEST_CHANGES ou BLOCK — posé comme statut de commit. C'est ce statut qui conditionne la fusion, laquelle reste déclenchée par un humain.

### 9. Méthodologie — ≈ 20 s

Le projet a suivi la méthode Scrumban, retenue après comparaison avec Scrum, Kanban et XP : la cadence et les jalons de Scrum, avec la discipline de flux de Kanban. Dix sprints de deux semaines sur cinq mois, et une étiquette Expedite pour traiter un incident de production sans replanifier le sprint en cours.

### 10. Divider 2 — ≈ 5 s

Passons à l'état de l'art et aux choix technologiques.

### 11. DevSecOps — ≈ 18 s

Le cadre conceptuel est le DevSecOps et le shift-left : détecter les vulnérabilités au plus tôt, dès la Pull Request, là où une faille coûte presque rien à corriger. Notre apport matérialise ce principe : le verdict de l'agent devient un gate technique qui conditionne la fusion.

### 12. Besoins — ≈ 18 s

Cinq besoins fonctionnels : détecter les vulnérabilités, produire la revue OWASP avec verdict, publier les commentaires sur GitHub, persister chaque revue, et offrir un assistant en langage naturel. Côté non fonctionnel, la contrainte dominante est la confidentialité : l'inférence reste locale.

### 13. Benchmark — ≈ 32 s

Le choix des modèles repose non sur la littérature, mais sur un banc d'essai sur le matériel cible, prompt système complet. Deux candidats éliminés : llama 3.2 trois milliards, saturé par le seul prompt système, et granite, dont l'appel d'outils est incompatible. Restent qwen2.5-coder 7B et 14B, à quatre-vingts pour cent de précision. D'où deux modèles : le 7B classifie, le 14B analyse. Le banc a aussi confirmé Ollama : vingt-deux pour cent de débit de plus que LocalAI, à poids identiques.

### 14. Technologies retenues — ≈ 30 s

Trois briques portent l'ensemble. Cinq scanners spécialisés : Trivy pour les CVE, Gitleaks pour les secrets, Semgrep pour le code applicatif, Checkov pour l'infrastructure, OSV-Scanner pour les dépendances. Deux modèles servis localement par Ollama. Et l'orchestrateur LangGraph, préféré à Prefect et Celery pour sa persistance d'état native dans PostgreSQL : un pipeline de vingt minutes survit au redémarrage de son conteneur. Détail qui compte : les sorties des scanners sont nettoyées avant transmission au modèle — cinquante-deux pour cent de tokens en moins — pour préserver la fenêtre de contexte.

### 15. Positionnement — ≈ 22 s

Pourquoi pas un outil du marché ? Aucun ne combine raisonnement par modèle de langage et inférence entièrement locale. CodeQL, Snyk et Copilot envoient le code à un tiers — rédhibitoire en banque. SonarQube est auto-hébergeable mais purement statique, sans explication. Notre contribution unit ces deux mondes, sans qu'une ligne ne sorte du VPS.

### 16. Divider 3 — ≈ 5 s

Venons-en à la conception.

### 17. Architecture — ≈ 25 s

La plateforme compte onze conteneurs Docker en quatre couches. L'entrée : nginx, seul point exposé, qui authentifie et transmet les webhooks. La couche IA : l'agent FastAPI, qui orchestre le graphe LangGraph et les scanners, et Ollama, accessible uniquement depuis le réseau Docker interne. Les données : PostgreSQL pour la base de connaissances et les checkpoints, Redis pour la déduplication et le cache. Et l'observabilité, sur laquelle je reviendrai.

### 18. Manifeste (builds : 6 clics) — ≈ 35 s

Ce point fonde le titre du projet : il s'agit d'un agent, et non d'un simple appel à un modèle. Six capacités le démontrent. [clics] Il perçoit son environnement — webhooks, métriques, alertes. Il raisonne : il classifie chaque Pull Request et route son graphe d'état en conséquence. Il agit : il commente, il bloque, il escalade vers Slack. Il persiste : son état est sauvegardé après chaque nœud, et il reprend exactement où il s'était arrêté. Il manipule dix-neuf outils réels. Et il s'auto-exploite : gardien disque et bilan de santé quotidien.

### 19. Pipeline (builds : 7 clics) — ≈ 42 s

Le cœur du système est un graphe d'état à neuf nœuds. Suivons une Pull Request. [clics] Le webhook est vérifié et dédupliqué ; le dépôt est cloné, le diff généré localement. Le 7B classifie en cinq catégories, et le routage adapte l'analyse : une PR de documentation saute les scanners, un Dockerfile déclenche le scan d'image. Les scanners tournent en parallèle, chacun isolé — si l'un échoue, le pipeline continue. Le 14B mène l'analyse OWASP, rend le verdict, escalade sur Slack si besoin, puis publie. Optimisation clé : fusionner les deux appels du 14B a fait passer le pipeline de trente-cinquante minutes à quinze-vingt-cinq.

### 20. Fiabilité — ≈ 35 s

Reste la question légitime : peut-on faire confiance à un modèle de langage ? Six couches de protection répondent. Trois agissent sur le modèle : température proche de zéro, fenêtre de contexte dimensionnée, génération plafonnée. Trois relèvent du contrôle applicatif : une garde qui force l'appel d'outil pour toute donnée en temps réel, des règles anti-hallucination dans le prompt, et l'interdiction de citer une valeur absente des observations. Pour la revue de code s'y ajoute un parser dédié, qui écarte tout commentaire visant une ligne inexistante du diff. Résultat : aucune erreur de ligne publiée sur GitHub.

### 21. Divider 4 — ≈ 5 s

Passons à la réalisation et aux résultats.

### 22. Environnement — ≈ 20 s

Le terrain d'exécution est volontairement contraint : un VPS de production de douze cœurs Haswell, quarante-cinq giga-octets de mémoire, sans GPU — c'est le prix de la confidentialité, et nous l'assumons. Cette contrainte a imposé un vrai tuning : flash attention et quantisation du cache KV pour tenir le modèle 14B en mémoire. La pile est intégralement open source.

### 23. Défense en profondeur — ≈ 30 s

La détection suit une logique de défense en profondeur : chaque scanner couvre une classe de risque — secrets, code, dépendances, infrastructure, images — et le modèle 14B consolide l'ensemble en une revue unique, priorisée, avec une suggestion de correction par point. Les findings des scanners restent déterministes : ils sont persistés en base quel que soit le texte produit par le modèle.

### 24a. Démonstration 1/3 : le code soumis — ≈ 25 s

La démonstration part d'une seule Pull Request, dans un dépôt de test. Trois fichiers : un module de virement en PHP qui concentre sept vulnérabilités types — injection SQL, injection de commande, SSRF, désérialisation non sécurisée, XSS, hachage MD5 et mot de passe transmis dans l'URL — avec en prime trois secrets codés en dur. À côté, un requirements aux dépendances obsolètes et un Dockerfile qui tourne en root. Le terrain de jeu idéal pour l'agent.

### 24b. Démonstration 2/3 : l'agent au travail — ≈ 30 s

Le développeur crée sa branche, pousse, ouvre la Pull Request — et n'a plus rien à faire. À droite, les journaux de l'agent défilent en direct : le webhook signé est vérifié, le modèle 7B classe la Pull Request, puis six scanners s'exécutent en parallèle — Semgrep remonte quarante-trois alertes, OSV cent onze vulnérabilités de dépendances, Trivy soixante-quatre. Tout se passe en local, sans qu'aucune ligne ne quitte la banque. Le modèle 14B prend alors le relais pour l'analyse approfondie.

### 24c. Démonstration 3/3 : verdict et revue inline — ≈ 30 s

Le résultat est publié directement sur la Pull Request. Une synthèse en tête — risque CRITIQUE, verdict BLOCK — puis huit commentaires inline, chacun ancré sur la ligne exacte du diff : l'injection SQL, la SSRF, le XSS, le MD5, le mot de passe en URL, et jusqu'au Dockerfile sans utilisateur. Chaque commentaire porte une suggestion de correction. [clic] Le statut du commit passe au rouge : la fusion est techniquement bloquée, et l'équipe est prévenue sur Slack. L'agent n'a pas seulement commenté — il a arrêté le code vulnérable à la porte.

### 25. Bénéfices & résultats — ≈ 25 s

Le tableau résume le passage du manuel à l'agent : un délai divisé par près de cent, une couverture OWASP systématique, un gate effectif là où rien ne bloquait, une traçabilité complète en base. Sur le jeu contrôlé, sept sur sept, sans faux positif dans le fichier modifié. Au-delà de la démonstration, huit revues réelles sont persistées en base, et leurs verdicts suivent le risque.

### 26a. Observabilité 1/2 : la stack — ≈ 18 s

L'agent voit l'intégralité du VPS : vingt-huit métriques, quinze règles d'alerte et trois tableaux de bord Grafana, rafraîchis toutes les trente secondes. Faute de compatibilité de cAdvisor avec notre version de Docker, les métriques de conteneurs passent directement par le socket Docker, et les deux moteurs d'inférence sont comparés en continu.

### 26b. Observabilité 2/2 : pannes détectées — ≈ 17 s

Et cette supervision n'est pas décorative : elle a révélé deux pannes restées invisibles — un AlertManager hors service depuis le déploiement initial, et une collecte VictoriaMetrics interrompue pendant neuf jours. Les deux, repérées par les tableaux de bord, puis corrigées en sprint.

### 27. Chat & autonomie — ≈ 25 s

Un assistant conversationnel doté de dix-neuf outils permet d'interroger l'infrastructure en langage naturel, jusqu'à la base de connaissances sécurité, sans écrire de SQL. Chaque question sur une donnée réelle déclenche l'appel d'outil correspondant : la réponse cite la valeur mesurée, jamais inventée. Et l'agent s'auto-exploite : gardien disque toutes les trente minutes, nettoyage automatique à quatre-vingt-dix pour cent, bilan de santé publié chaque matin sur Slack.

### 28. Phi-4 — ≈ 22 s

Un épisode révélateur : la télémétrie a détecté qu'un modèle candidat, Phi-4, renvoyait zéro token sans la moindre erreur journalisée — un template de conversation mal formé. Corrigé, puis vérifié : de zéro à cinquante et un tokens. Le système a repéré une panne invisible aux journaux : la preuve qu'il se surveille lui-même.

### 29. Tests et validation — ≈ 20 s

La validation finale a couvert les mécanismes critiques : signature invalide rejetée avant tout traitement, webhook dupliqué ignoré, circuit breaker avec classification de repli si le modèle est indisponible, gardien disque vérifié en conditions réelles. Au total, quatorze vérifications de bout en bout, toutes validées avant la livraison.

### 30. Divider 5 — ≈ 5 s

J'en viens à la conclusion.

### 31. Limites assumées & perspectives — ≈ 40 s

Deux limites assumées et un point de vigilance. L'inférence sur CPU borne la revue à quinze-vingt-cinq minutes : c'est le prix de la confidentialité. Le corpus d'évaluation reste restreint — un jeu contrôlé et huit revues réelles. Et le diff analysé est par nature une entrée non fiable : l'architecture y oppose déjà les findings déterministes des scanners, qu'aucun texte ne peut effacer, et le plan de durcissement prévoit d'ancrer davantage le verdict sur ces findings. Trois perspectives : la migration GPU — environ trois mille euros, dans l'enveloppe de la DCIO — ramènerait chaque revue à deux à cinq minutes, sans toucher ni à l'architecture ni à la confidentialité ; le passage à l'échelle de l'ensemble des dépôts de la banque ; et un tableau de bord de risque alimenté par les revues accumulées, destiné au RSSI.

### 32. Conclusion — ≈ 30 s

En conclusion : parti d'un VPS vierge, ce projet livre un agent d'intelligence artificielle complet, déployé en production à la BTE, qui sécurise chaque Pull Request sans qu'aucun code ne quitte la banque. La plateforme est remise à la banque et constitue un socle concret pour sa transformation DevSecOps. Je vous remercie de votre attention et me tiens à votre disposition pour répondre à vos questions.


---

## Annexe — Démo « les six scanners » : logs réels et narration (PR #22)

> Capture du 2026-06-28 sur `GhaiethFerchichi/Vunl-application`, branche `demo/audit-complet`, après correction de trois bogues de scanners (tag Docker en minuscules ; OSV-Scanner v2 `scan source --format json` ; Gitleaks `--no-git`). À conserver comme référence des chiffres exacts montrés dans la vidéo des logs.

### Chiffres réels du run (task `45ca18c2`)

| Étape / scanner | Log | Résultat |
|---|---|---|
| Réception | `webhook_received` action=opened → `webhook_dispatched` pr=22 → 202 | webhook signé, accusé immédiat |
| Intake | `intake_complete` | diff 1954 o, 3 fichiers, Dockerfile présent |
| Classification (7B) | `classify_complete` | `infrastructure`, risque moyen, 27,8 s |
| Image Docker | `docker_build_success` (tag `…pr-22:scan` en minuscules) | build OK → scan d'image activé |
| `scanning_dependencies` — **osv** | `osv_parsed count=111` | 111 vulns de dépendances (requirements.txt) |
| `scanning_iac` — **checkov** | `checkov_parsed failed=3 passed=4` | 3 mauvaises configs (Dockerfile) |
| `scanning_sast` — **semgrep** | `semgrep_parsed count=43` (36 ERROR) | 43 alertes SAST sur le code |
| `scanning_secrets` — **gitleaks** | `gitleaks_findings count=3` ¹ | 3 secrets en dur (JWT, jeton interne, mot de passe BD) |
| `scanning_filesystem` — **trivy** | `trivy_parsed trivy_fs total=64` | 64 vulns (9 CRIT / 26 HIGH / 29 MED) |
| `scanning_image` — **trivy** | `trivy_parsed trivy_image total=6324` | CVEs de l'image de base python:3.8 ² |
| Agrégation | `scan_full_complete scanners=['trivy_fs','gitleaks','trivy_image','semgrep','checkov','osv']` | les six ont statué |
| Analyse (14B) | `analyze_review_start` | revue approfondie, ~10 min CPU |
| Supervision | `slack_notification_sent` | notification équipe |

¹ Dans le premier run capturé, Gitleaks affichait `gitleaks_clean` : la branche avait été clonée avant l'ajout des secrets (push protection GitHub). Après re-déclenchement, Gitleaks détecte bien 3 secrets. *Penser à vider le cache Redis (`scan:*`) avant chaque run de démo pour que les scanners s'exécutent à frais — sinon `scan_cache_hit`.*
² Les 6324 CVEs proviennent des couches de l'image de base `python:3.8`, et non du code du candidat. Le couplage `scanning_image` → service `trivy` audite l'image complète, base comprise.

### Narration (≈ 70 s) — la vidéo des logs + notification Slack

> Dès qu'un développeur ouvre une pull request, GitHub envoie un webhook signé à l'agent. On le voit en haut de l'écran : `webhook_received`, action `opened`, puis `webhook_dispatched`. L'agent répond aussitôt par un 202 et prend la main.
>
> Première étape, l'*intake* : il clone la branche, calcule le diff — trois fichiers ici — et repère la présence d'un Dockerfile. En moins d'une seconde, il dispose de tout le contexte.
>
> Vient ensuite la classification. Le modèle 7B lit le diff et range la pull request : `classification=infrastructure`, risque moyen. Cette décision détermine quels scanners seront lancés.
>
> Et voici le cœur du système. L'agent déclenche six scanners en parallèle, chacun spécialisé. On les voit s'allumer ligne par ligne, couplés à leur service :
> — `scanning_dependencies`, service **osv** : 111 vulnérabilités dans les dépendances de requirements.txt ;
> — `scanning_iac`, service **checkov** : trois mauvaises configurations dans le Dockerfile ;
> — `scanning_sast`, service **semgrep** : 43 alertes sur le code, dont 36 erreurs ;
> — `scanning_secrets`, service **gitleaks** : trois secrets codés en dur — la clé JWT, le jeton interne et le mot de passe de la base ;
> — `scanning_filesystem`, service **trivy** : 64 vulnérabilités, dont 9 critiques ;
> — et `scanning_image`, toujours **trivy**, qui audite l'image Docker construite à partir de python:3.8.
>
> Ligne suivante, `scan_full_complete` : les six scanners ont rendu leur verdict. L'agent agrège l'ensemble et le transmet au modèle 14B pour l'analyse approfondie.

#### Beat Slack — capture séparée (≈ 10 s)

À enchaîner après la vidéo des logs, sur la capture d'écran Slack :

> Et l'agent ne se limite pas à analyser : voici la notification reçue côté Slack. L'équipe est prévenue en temps réel, et chaque décision laisse une trace.

#### Variante si la vidéo conservée montre `gitleaks_clean`

> — `scanning_secrets`, service **gitleaks** : aucun secret détecté par signature sur ce commit. C'est précisément là qu'intervient le modèle 14B, qui repérera ensuite la clé codée en dur que les règles de signature laissent passer — la détection par motif et le raisonnement du modèle se complètent.
