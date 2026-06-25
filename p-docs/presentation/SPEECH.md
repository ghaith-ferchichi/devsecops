# Discours de soutenance — BTE Security AI Agent

**Version 15 minutes** — durée totale ≈ 14 min 30 s (32 diapositives).

Les marqueurs `[clic]` correspondent aux animations des diapositives 7, 18, 19 et 24.

## Minutage

| # | Diapositive | Durée |
|---|---|---|
| 1 | BTE Security | 30 s |
| 2 | Sommaire | 10 s |
| 3 | Une seule injection SQL fusionnée dans une API de paiement | 35 s |
| 4 | 01 | 5 s |
| 5 | Organisme d'accueil et étude de l'existant | 30 s |
| 6 | Problématique | 30 s |
| 7 | 24 h → 15 min | 40 s |
| 8 | Solution proposée (TO-BE) | 30 s |
| 9 | Méthodologie de travail | 30 s |
| 10 | 02 | 5 s |
| 11 | DevSecOps et approche shift-left | 25 s |
| 12 | Spécification des besoins | 25 s |
| 13 | Choix des modèles LLM — benchmark sur le matériel cible | 45 s |
| 14 | Technologies retenues | 30 s |
| 15 | Positionnement par rapport aux solutions existantes | 30 s |
| 16 | 03 | 5 s |
| 17 | Architecture globale de la solution | 25 s |
| 18 | Un agent autonome, et non un simple appel LLM | 35 s |
| 19 | Le pipeline de revue — graphe d'état LangGraph | 50 s |
| 20 | Fiabilité — anti-hallucination et deux modèles | 35 s |
| 21 | 04 | 5 s |
| 22 | Environnement de travail | 20 s |
| 23 | Défense en profondeur — cinq scanners et un LLM | 30 s |
| 24 | Démonstration — Pull Request #18 | 50 s |
| 25 | 5 / 5 | 25 s |
| 26 | Supervision complète du VPS | 35 s |
| 27 | Assistant conversationnel et opérations autonomes | 25 s |
| 28 | 0 → 51 | 35 s |
| 29 | Tests et validation de la plateforme | 20 s |
| 30 | 05 | 5 s |
| 31 | Limites assumées et perspectives | 40 s |
| 32 | Un agent IA agentique, déployé en production à la BTE, | 30 s |
| | **Total** | **≈ 14:30** |

---

## Discours

### 1. BTE Security — ≈ 30 s

Monsieur le Président du jury, Madame, Messieurs les membres du jury, bonjour. Je m'appelle Ghaith Ferchichi et j'ai l'honneur de vous présenter mon projet de fin d'études, réalisé au sein de la Banque de Tunisie et des Émirats, sous l'encadrement de Monsieur Kamel Kaouech, côté banque, et de Madame Ghayet El Mouna Zhioua, côté ISI. Il s'intitule BTE Security AI Agent : un agent d'intelligence artificielle pour la revue automatisée de code.

### 2. Sommaire — ≈ 10 s

Mon exposé suit la structure du rapport : le contexte général, l'état de l'art et les choix technologiques, la conception de l'agent, sa réalisation et ses résultats, puis la conclusion et les perspectives.

### 3. Une seule injection SQL fusionnée dans une API de paiement — ≈ 35 s

Partons de trois scénarios concrets : une injection SQL fusionnée dans une API de paiement, un secret d'authentification commité par mégarde dans un dépôt, une image Docker bâtie sur une bibliothèque exposée à un CVE critique. Chacune de ces failles peut compromettre le système d'information de la banque. Or, à la BTE, la revue de sécurité du code est entièrement manuelle : elle peut atteindre vingt-quatre heures, et sa qualité dépend de la disponibilité et de l'expertise du relecteur du jour. C'est ce constat qui motive ce travail.

### 4. 01 — ≈ 5 s

Commençons par le contexte général.

### 5. Organisme d'accueil et étude de l'existant — ≈ 30 s

La BTE est née en 1982 d'une convention entre l'État tunisien et l'Abu Dhabi Investment Authority. Mon stage s'est déroulé à la Direction Centrale de l'Informatique et de l'Organisation, auprès des équipes de sécurité opérationnelle. Le processus existant, à gauche, repose sur GitHub : à l'ouverture d'une Pull Request, un développeur senior ou un référent sécurité examine le diff à la main, commente, puis déclenche la fusion. Aucune analyse statique, aucun scanner, aucun gate de pipeline : tout repose sur l'examen humain.

### 6. Problématique — ≈ 30 s

Quatre limites en découlent. Le délai, d'abord : jusqu'à vingt-quatre heures, pendant lesquelles la vulnérabilité reste exposée. L'absence de blocage technique, ensuite : une Pull Request porteuse d'une faille critique peut être fusionnée sans obstacle. Une qualité de revue qui varie d'un relecteur à l'autre. Et deux angles morts structurels : les secrets commités par accident et les dépendances vulnérables, deux catégories pour lesquelles l'œil humain n'est pas le bon outil.

### 7. 24 h → 15 min — ≈ 40 s

Notre contribution tient en une phrase : un agent d'intelligence artificielle autonome qui revoit chaque Pull Request selon la grille OWASP Top 10, publie ses correctifs directement sur GitHub, et s'exécute intégralement en local — aucun code ne quitte la banque. Trois chiffres résument le résultat. [clic] Le délai de revue passe de vingt-quatre heures à une quinzaine de minutes. [clic] Sur la validation contrôlée, cinq vulnérabilités sur cinq sont détectées, sans faux positif dans le fichier modifié. [clic] Et cent pour cent de l'inférence reste sur le VPS de la banque, conformément aux exigences de la Banque Centrale de Tunisie.

### 8. Solution proposée (TO-BE) — ≈ 30 s

Voici le processus cible. GitHub émet un webhook signé HMAC-SHA256 ; l'agent vérifie la signature, élimine les doublons, classifie la Pull Request en une trentaine de secondes, exécute en parallèle les scanners pertinents, puis consolide leurs résultats avec un modèle de langage local. Il publie sur GitHub la revue complète : score de risque, commentaires ligne par ligne et verdict — APPROVE, REQUEST_CHANGES ou BLOCK — posé comme statut de commit. C'est ce statut qui conditionne la fusion, laquelle reste déclenchée par un humain.

### 9. Méthodologie de travail — ≈ 30 s

Le projet a été conduit selon la méthode Scrumban, retenue après comparaison avec Scrum, Kanban et XP : elle combine la cadence et les jalons de Scrum, utiles à l'encadrement, avec la discipline de flux de Kanban — un travail en cours limité à une seule carte. Dix sprints de deux semaines sur cinq mois, six jalons, et une étiquette Expedite qui permettait à un incident de production de passer devant tout le reste, sans replanifier le sprint en cours.

### 10. 02 — ≈ 5 s

Passons à l'état de l'art et aux choix technologiques.

### 11. DevSecOps et approche shift-left — ≈ 25 s

Le cadre conceptuel est le DevSecOps et son principe de shift-left : déplacer la détection des vulnérabilités au plus tôt du cycle, idéalement dès la Pull Request, là où une faille ne coûte presque rien à corriger comparée à la même faille découverte en production. Notre apport matérialise ce principe : le verdict de l'agent devient un gate technique, qui conditionne réellement la fusion.

### 12. Spécification des besoins — ≈ 25 s

Cinq besoins fonctionnels : détecter les vulnérabilités à chaque Pull Request, produire la revue OWASP avec score et verdict, publier les commentaires sur GitHub, persister chaque revue en base de connaissances, et offrir un assistant d'exploitation en langage naturel. Côté non fonctionnel, la contrainte dominante est la confidentialité — l'inférence doit rester locale —, complétée par la performance, la résilience par circuit breaker et l'observabilité complète.

### 13. Choix des modèles LLM — benchmark sur le matériel cible — ≈ 45 s

Le choix des modèles ne repose pas sur la littérature, mais sur un banc d'essai mené sur le matériel cible, avec le prompt système complet. Deux candidats sont éliminés : llama 3.2 trois milliards, dont la fenêtre de contexte est saturée par le seul prompt système — sa précision tombe à zéro —, et granite, dont le schéma d'appel d'outils est incompatible. Restent qwen2.5-coder 7B et 14B, à égalité de précision à quatre-vingts pour cent. D'où une architecture à deux modèles : le 7B classifie en trente secondes, le 14B mène l'analyse approfondie. Un benchmark croisé a par ailleurs confirmé le moteur Ollama : vingt-deux pour cent de débit de plus que LocalAI, sur un fichier de poids strictement identique.

### 14. Technologies retenues — ≈ 30 s

Trois briques portent l'ensemble. Cinq scanners spécialisés : Trivy pour les CVE, Gitleaks pour les secrets, Semgrep pour le code applicatif, Checkov pour l'infrastructure, OSV-Scanner pour les dépendances. Deux modèles servis localement par Ollama. Et l'orchestrateur LangGraph, préféré à Prefect et Celery pour sa persistance d'état native dans PostgreSQL : un pipeline de vingt minutes survit au redémarrage de son conteneur. Détail qui compte : les sorties des scanners sont nettoyées avant transmission au modèle — cinquante-deux pour cent de tokens en moins — pour préserver la fenêtre de contexte.

### 15. Positionnement par rapport aux solutions existantes — ≈ 30 s

Pourquoi ne pas avoir adopté un outil du marché ? Parce qu'aucun ne combine raisonnement par modèle de langage et inférence entièrement locale. CodeQL, Snyk et Copilot Autofix transmettent le code à une infrastructure tierce — rédhibitoire en contexte bancaire. SonarQube est auto-hébergeable, mais purement statique, sans explication en langage naturel. Notre contribution est l'intégration de ces deux mondes, sans qu'une ligne de code ne sorte du VPS.

### 16. 03 — ≈ 5 s

Venons-en à la conception.

### 17. Architecture globale de la solution — ≈ 25 s

La plateforme compte onze conteneurs Docker en quatre couches. L'entrée : nginx, seul point exposé, qui authentifie et transmet les webhooks. La couche IA : l'agent FastAPI, qui orchestre le graphe LangGraph et les scanners, et Ollama, accessible uniquement depuis le réseau Docker interne. Les données : PostgreSQL pour la base de connaissances et les checkpoints, Redis pour la déduplication et le cache. Et l'observabilité, sur laquelle je reviendrai.

### 18. Un agent autonome, et non un simple appel LLM — ≈ 35 s

Ce point fonde le titre du projet : il s'agit d'un agent, et non d'un simple appel à un modèle. Six capacités le démontrent. [clics] Il perçoit son environnement — webhooks, métriques, alertes. Il raisonne : il classifie chaque Pull Request et route son graphe d'état en conséquence. Il agit : il commente, il bloque, il escalade vers Slack. Il persiste : son état est sauvegardé après chaque nœud, et il reprend exactement où il s'était arrêté. Il manipule dix-neuf outils réels. Et il s'auto-exploite : gardien disque et bilan de santé quotidien.

### 19. Le pipeline de revue — graphe d'état LangGraph — ≈ 50 s

Le cœur du système est un graphe d'état à neuf nœuds. Suivons une Pull Request. [clics] Le webhook est vérifié et dédupliqué ; le dépôt est cloné et le diff généré localement avec quinze lignes de contexte. Le modèle 7B classifie en cinq catégories. Le routage adapte l'analyse : une PR de documentation saute les scanners, un Dockerfile déclenche le scan d'image complet. Les scanners s'exécutent en parallèle, chacun isolé dans sa coroutine — si l'un échoue, le pipeline continue. Le 14B mène ensuite l'analyse OWASP sur un diff annoté de numéros de lignes ; le verdict est rendu, avec escalade Slack si le risque est élevé, puis la revue est publiée. Une optimisation a changé l'échelle : la fusion des deux appels du 14B en un seul a fait passer le pipeline de trente-cinquante minutes à quinze-vingt-cinq.

### 20. Fiabilité — anti-hallucination et deux modèles — ≈ 35 s

Reste la question légitime : peut-on faire confiance à un modèle de langage ? Six couches de protection répondent. Trois agissent sur le modèle : température proche de zéro, fenêtre de contexte dimensionnée, génération plafonnée. Trois relèvent du contrôle applicatif : une garde qui force l'appel d'outil pour toute donnée en temps réel, des règles anti-hallucination dans le prompt, et l'interdiction de citer une valeur absente des observations. Pour la revue de code s'y ajoute un parser dédié, qui écarte tout commentaire visant une ligne inexistante du diff. Résultat : aucune erreur de ligne publiée sur GitHub.

### 21. 04 — ≈ 5 s

Passons à la réalisation et aux résultats.

### 22. Environnement de travail — ≈ 20 s

Le terrain d'exécution est volontairement contraint : un VPS de production de douze cœurs Haswell, quarante-cinq giga-octets de mémoire, sans GPU — c'est le prix de la confidentialité, et nous l'assumons. Cette contrainte a imposé un vrai tuning : flash attention et quantisation du cache KV pour tenir le modèle 14B en mémoire. La pile est intégralement open source.

### 23. Défense en profondeur — cinq scanners et un LLM — ≈ 30 s

La détection suit une logique de défense en profondeur : chaque scanner couvre une classe de risque, et le modèle consolide l'ensemble en une revue unique. Les deux niveaux se complètent réellement : sur la démonstration, c'est le modèle qui a détecté des secrets en dur que Gitleaks n'avait pas signalés. Et les findings des scanners sont déterministes : ils sont persistés en base quel que soit le texte produit par le modèle.

### 24. Démonstration — Pull Request #18 — ≈ 50 s

Voici la démonstration, sur la Pull Request numéro dix-huit : un module bancaire en PHP contenant cinq vulnérabilités types — injection SQL, secrets en dur, path traversal, injection de commande et hachage MD5. À l'écran, la revue publiée par l'agent défile : l'analyse de chaque faille, puis les recommandations. [clic] Le verdict tombe : BLOCK. Cinq commentaires inline, chacun avec une suggestion de correction applicable en un clic depuis GitHub, et le statut de commit passe en échec : la fusion est techniquement bloquée tant que les corrections ne sont pas poussées. Durée totale pour cette revue : une quinzaine de minutes, notification Slack comprise.

### 25. 5 / 5 — ≈ 25 s

Le tableau résume le passage du manuel à l'agent : un délai divisé par près de cent, une couverture OWASP systématique, un gate effectif là où rien ne bloquait, une traçabilité complète en base. Sur le jeu contrôlé, cinq sur cinq, sans faux positif dans le fichier modifié. Au-delà de la démonstration, huit revues réelles sont persistées en base, et leurs verdicts suivent le risque.

### 26. Supervision complète du VPS — ≈ 35 s

L'agent voit l'intégralité du VPS : vingt-huit métriques personnalisées, quinze règles d'alerte, trois tableaux de bord Grafana. Les dernières métriques interrogent directement le socket Docker — après l'échec de cAdvisor sur notre version de Docker — et comparent les deux moteurs d'inférence. Cette supervision n'est pas décorative : elle a révélé un AlertManager silencieusement hors service depuis le déploiement initial, et une panne de VictoriaMetrics restée neuf jours invisible. Deux anomalies détectées, puis corrigées en sprint.

### 27. Assistant conversationnel et opérations autonomes — ≈ 25 s

Un assistant conversationnel doté de dix-neuf outils permet d'interroger l'infrastructure en langage naturel, jusqu'à la base de connaissances sécurité, sans écrire de SQL. Chaque question sur une donnée réelle déclenche l'appel d'outil correspondant : la réponse cite la valeur mesurée, jamais inventée. Et l'agent s'auto-exploite : gardien disque toutes les trente minutes, nettoyage automatique à quatre-vingt-dix pour cent, bilan de santé publié chaque matin sur Slack.

### 28. 0 → 51 — ≈ 35 s

L'épisode le plus révélateur du projet : la télémétrie a mis en évidence un bug du modèle Phi-4, qui renvoyait zéro token alors que la requête se terminait sans aucune erreur journalisée. La cause : un template de conversation mal formé, qui présentait au modèle une conversation déjà close. Le correctif a été aligné sur la configuration officielle du modèle, puis vérifié : de zéro à cinquante et un tokens. Le système a détecté une panne invisible aux journaux — c'est la meilleure preuve qu'il se surveille lui-même.

### 29. Tests et validation de la plateforme — ≈ 20 s

La validation finale a couvert les mécanismes critiques : signature invalide rejetée avant tout traitement, webhook dupliqué ignoré, circuit breaker avec classification de repli si le modèle est indisponible, gardien disque vérifié en conditions réelles. Au total, quatorze vérifications de bout en bout, toutes validées avant la livraison.

### 30. 05 — ≈ 5 s

J'en viens à la conclusion.

### 31. Limites assumées et perspectives — ≈ 40 s

Deux limites assumées et un point de vigilance. L'inférence sur CPU borne la revue à quinze-vingt-cinq minutes : c'est le prix de la confidentialité. Le corpus d'évaluation reste restreint — un jeu contrôlé et huit revues réelles. Et le diff analysé est par nature une entrée non fiable : l'architecture y oppose déjà les findings déterministes des scanners, qu'aucun texte ne peut effacer, et le plan de durcissement prévoit d'ancrer davantage le verdict sur ces findings. Trois perspectives : la migration GPU — environ trois mille euros, dans l'enveloppe de la DCIO — ramènerait chaque revue à deux à cinq minutes, sans toucher ni à l'architecture ni à la confidentialité ; le passage à l'échelle de l'ensemble des dépôts de la banque ; et un tableau de bord de risque alimenté par les revues accumulées, destiné au RSSI.

### 32. Un agent IA agentique, déployé en production à la BTE, — ≈ 30 s

En conclusion : parti d'un VPS vierge, ce projet livre un agent d'intelligence artificielle complet, déployé en production à la BTE, qui sécurise chaque Pull Request sans qu'aucun code ne quitte la banque. La plateforme est remise à la banque et constitue un socle concret pour sa transformation DevSecOps. Je vous remercie de votre attention et me tiens à votre disposition pour répondre à vos questions.

