# Discours de soutenance — BTE Security AI Agent

> Généré depuis les **notes orateur** du `.pptx` (mode Présentateur de PowerPoint
> les affiche automatiquement). Régénérer après toute modification :
> `python3 build_pptx_modern.py` puis ce script.

**Durée totale estimée : ≈ 18 min 20 s** (répéter pour ajuster ; prévoir une marge
sur un créneau de 20 minutes).

## Minutage

| # | Slide | Temps |
|---|-------|-------|
| 1 | BTE Security | 35 s |
| 2 | Sommaire | 20 s |
| 3 | Une seule injection SQL fusionnée dans une API de pa | 40 s |
| 4 | 01 | 5 s |
| 5 | Organisme d'accueil et étude de l'existant | 45 s |
| 6 | Problématique | 40 s |
| 7 | 24 h → 15 min | 45 s |
| 8 | Solution proposée (TO-BE) | 40 s |
| 9 | Méthodologie de travail | 40 s |
| 10 | 02 | 5 s |
| 11 | DevSecOps et approche shift-left | 30 s |
| 12 | Spécification des besoins | 40 s |
| 13 | Choix des modèles LLM — benchmark sur le matériel ci | 50 s |
| 14 | Technologies retenues | 40 s |
| 15 | Positionnement par rapport aux solutions existantes | 35 s |
| 16 | 03 | 5 s |
| 17 | Architecture globale de la solution | 40 s |
| 18 | Un agent autonome, et non un simple appel LLM | 45 s |
| 19 | Le pipeline de revue — graphe d'état LangGraph | 55 s |
| 20 | Fiabilité — anti-hallucination et deux modèles | 45 s |
| 21 | 04 | 5 s |
| 22 | Environnement de travail | 30 s |
| 23 | Défense en profondeur — cinq scanners et un LLM | 40 s |
| 24 | Démonstration — Pull Request #18 | 50 s |
| 25 | 5 / 5 | 40 s |
| 26 | Supervision complète du VPS | 40 s |
| 27 | Assistant conversationnel et opérations autonomes | 40 s |
| 28 | 0 → 51 | 35 s |
| 29 | Tests et validation de la plateforme | 35 s |
| 30 | 05 | 5 s |
| 31 | Limites et perspectives | 50 s |
| 32 | Un agent IA agentique, déployé en production à la BT | 30 s |

---
## Texte intégral, slide par slide

## Slide 1 — BTE Security
*(≈ 35 s)*

Monsieur le Président du jury, Madame, Messieurs les membres du jury, bonjour. Je m'appelle Ghaith Ferchichi et j'ai l'honneur de vous présenter mon projet de fin d'études, réalisé au sein de la Banque de Tunisie et des Émirats en vue de l'obtention du Diplôme National de Mastère Professionnel, spécialité Sécurité des Systèmes d'Information et des Infrastructures. Ce travail a été encadré par Monsieur Kamel Kaouech, côté banque, et par Madame Ghayet El Mouna Zhioua, côté ISI. Il s'intitule BTE Security AI Agent : un agent d'intelligence artificielle pour la revue automatisée de sécurité du code.


## Slide 2 — Sommaire
*(≈ 20 s)*

Mon exposé suit la structure du rapport, en cinq chapitres : le contexte général du projet ; l'état de l'art et les choix technologiques ; la conception de l'agent ; sa réalisation et ses résultats ; et enfin la conclusion et les perspectives.


## Slide 3 — Une seule injection SQL fusionnée dans une API de paiement
*(≈ 40 s)*

Pour situer l'enjeu, partons de trois scénarios concrets : une injection SQL fusionnée dans une API de paiement, un secret d'authentification commité par mégarde dans un dépôt Git, une image Docker bâtie sur une bibliothèque exposée à un CVE critique. Chacune de ces failles peut compromettre l'intégrité du système d'information et engager la responsabilité de la banque, vis-à-vis de ses clients comme de ses régulateurs. Or, à la BTE, la revue de sécurité du code demeure entièrement manuelle : elle peut atteindre vingt-quatre heures, et sa qualité dépend de la disponibilité et de l'expertise du relecteur du jour. C'est ce constat qui motive ce travail.


## Slide 4 — 01
*(≈ 5 s)*

Commençons par le contexte général.


## Slide 5 — Organisme d'accueil et étude de l'existant
*(≈ 45 s)*

La BTE, créée en 1982, est née d'un partenariat entre l'État tunisien et l'Abu Dhabi Investment Authority ; banque d'investissement à l'origine, elle est devenue banque universelle en 2004. Mon stage s'est déroulé au sein du pôle Sécurité de la Direction des Systèmes d'Information. Le processus existant, que vous voyez à gauche, s'appuie sur GitHub : à l'ouverture d'une Pull Request, les code owners sont notifiés, un développeur senior ou un référent sécurité examine le diff à la main, dépose ses commentaires, puis déclenche la fusion. Aucune analyse statique, aucun scanner, aucun gate de pipeline n'est greffé sur ce cycle : tout repose sur l'examen humain.


## Slide 6 — Problématique
*(≈ 40 s)*

Quatre limites en découlent. D'abord le délai : jusqu'à vingt-quatre heures, pendant lesquelles la vulnérabilité reste exposée et la livraison bloquée. Ensuite l'absence de tout blocage technique : une Pull Request porteuse d'une faille critique peut être fusionnée sans obstacle. La qualité de la revue, elle, varie d'un relecteur à l'autre. Restent enfin les angles morts : les secrets commités par accident et les dépendances vulnérables introduites en transitif, deux catégories pour lesquelles l'œil humain n'est pas le bon outil.


## Slide 7 — 24 h → 15 min
*(≈ 45 s)*

Notre contribution tient en une phrase : un agent d'intelligence artificielle autonome qui revoit chaque Pull Request selon la grille OWASP Top 10, publie ses correctifs directement sur GitHub, et s'exécute intégralement en local — aucun code ne quitte la banque. Trois chiffres résument le résultat. [clic] Le délai de revue passe de vingt-quatre heures à une quinzaine de minutes. [clic] Sur la validation contrôlée, cinq vulnérabilités sur cinq sont détectées, sans faux positif dans le fichier modifié. [clic] Et la conformité aux exigences de la Banque Centrale est garantie : cent pour cent de l'inférence reste sur le VPS de la banque.


## Slide 8 — Solution proposée (TO-BE)
*(≈ 40 s)*

Concrètement, voici le processus cible. GitHub émet un webhook signé HMAC-SHA256 ; l'agent en vérifie la signature, élimine les doublons, puis classifie la Pull Request en une trentaine de secondes. Selon cette classification, il exécute en parallèle les scanners pertinents, consolide leurs résultats avec un modèle de langage local, et publie le tout sur GitHub : revue complète, score de risque, commentaires ligne par ligne et verdict — APPROVE, REQUEST_CHANGES ou BLOCK. Ce verdict est posé comme statut de commit : c'est lui qui conditionne la fusion, laquelle reste déclenchée par un humain.


## Slide 9 — Méthodologie de travail
*(≈ 40 s)*

Le projet a été conduit selon la méthode Scrumban, retenue après comparaison avec Scrum, Kanban et XP : elle combine la cadence de sprints et les jalons de Scrum, utiles à l'encadrement, avec la discipline de flux de Kanban — un travail en cours limité à une seule carte. Dix sprints de deux semaines sur cinq mois, rythmés par six jalons. Une étiquette Expedite autorisait les incidents de production à passer devant tout le reste : c'est ainsi qu'ont été absorbés l'urgence disque et la réécriture du parser de revue, sans replanifier les sprints en cours.


## Slide 10 — 02
*(≈ 5 s)*

Passons à l'état de l'art et aux choix technologiques.


## Slide 11 — DevSecOps et approche shift-left
*(≈ 30 s)*

Le cadre conceptuel est le DevSecOps et son principe de shift-left : déplacer la détection des vulnérabilités au plus tôt du cycle, idéalement dès la Pull Request, là où une faille ne coûte presque rien à corriger comparée à la même faille découverte en production. Notre apport consiste à matérialiser ce principe : le verdict de l'agent devient un gate technique, qui conditionne réellement la fusion.


## Slide 12 — Spécification des besoins
*(≈ 40 s)*

Côté besoins fonctionnels, la plateforme couvre cinq fonctions : détecter les vulnérabilités à chaque Pull Request, produire la revue OWASP avec score et verdict, publier les commentaires sur GitHub, persister chaque revue en base de connaissances, et offrir un assistant d'exploitation en langage naturel. Côté non fonctionnel, la contrainte dominante est la confidentialité : l'inférence doit rester locale, conformément aux exigences de la Banque Centrale de Tunisie. S'y ajoutent la performance — un pipeline en quinze à vingt-cinq minutes —, la résilience par circuit breaker, la fiabilité par checkpoints persistés, et l'observabilité complète de la plateforme.


## Slide 13 — Choix des modèles LLM — benchmark sur le matériel cible
*(≈ 50 s)*

Le choix des modèles ne repose pas sur la littérature, mais sur un banc d'essai mené sur le matériel cible, avec le prompt système complet. Deux candidats sont éliminés : llama 3.2 trois milliards, dont la fenêtre de contexte est saturée par le seul prompt système — sa précision tombe à zéro —, et granite, dont le schéma d'appel d'outils propriétaire est incompatible. Restent qwen2.5-coder 7B et 14B, à égalité de précision — quatre-vingts pour cent —, le 7B étant quarante-trois pour cent plus rapide par token. D'où une architecture à deux modèles : le 7B classifie en trente secondes, le 14B mène l'analyse approfondie. Un benchmark croisé a par ailleurs confirmé le choix du moteur Ollama : vingt-deux pour cent de débit de plus que LocalAI, sur un fichier de poids strictement identique.


## Slide 14 — Technologies retenues
*(≈ 40 s)*

L'ensemble s'appuie sur trois briques. Cinq scanners spécialisés, chacun couvrant une classe de risque : Trivy pour les CVE, Gitleaks pour les secrets, Semgrep pour le code applicatif, Checkov pour l'infrastructure, OSV-Scanner pour les dépendances. Deux modèles de langage servis localement par Ollama. Et l'orchestrateur LangGraph, préféré à Prefect et Celery pour sa persistance d'état native dans PostgreSQL : un pipeline de vingt minutes survit ainsi au redémarrage de son conteneur. J'ajoute un détail qui compte : les sorties des scanners sont nettoyées avant transmission au modèle — cinquante-deux pour cent de tokens en moins — afin de préserver la fenêtre de contexte pour l'analyse du code.


## Slide 15 — Positionnement par rapport aux solutions existantes
*(≈ 35 s)*

Pourquoi ne pas avoir adopté un outil du marché ? Parce qu'aucun ne combine raisonnement par modèle de langage et inférence entièrement locale. CodeQL, Snyk et Copilot Autofix transmettent le code à une infrastructure tierce — rédhibitoire en contexte bancaire. SonarQube reste auto-hébergeable, mais s'appuie sur des règles statiques, sans explication ni suggestion en langage naturel. Notre contribution n'est donc pas un nouvel algorithme de détection : c'est l'intégration de ces deux mondes, sans qu'une ligne de code ne sorte du VPS.


## Slide 16 — 03
*(≈ 5 s)*

Venons-en à la conception.


## Slide 17 — Architecture globale de la solution
*(≈ 40 s)*

La plateforme compte onze conteneurs Docker organisés en quatre couches. La couche d'entrée : nginx, seul point exposé, sur les ports 80 et 443, qui applique l'authentification et transmet les webhooks. La couche IA : l'agent FastAPI, qui orchestre le graphe LangGraph et exécute les scanners, et Ollama, accessible uniquement depuis le réseau Docker interne. La couche données : PostgreSQL, qui tient la base de connaissances sécurité et les checkpoints, et Redis, pour la déduplication, le rate limiting et le cache des résultats. Et la couche observabilité, sur laquelle je reviendrai en détail.


## Slide 18 — Un agent autonome, et non un simple appel LLM
*(≈ 45 s)*

J'insiste sur ce point, car il fonde le titre du projet : il s'agit d'un agent, et non d'un simple appel à un modèle. Six capacités le démontrent. [clics] Il perçoit son environnement — les événements GitHub, les métriques, les alertes. Il raisonne : il classifie chaque Pull Request et route son graphe d'état en conséquence. Il agit : il commente, il bloque, il escalade vers Slack. Il persiste : son état est sauvegardé après chaque nœud, et il reprend exactement où il s'était arrêté après un redémarrage. Il manipule dix-neuf outils réels. Et il s'auto-exploite : il surveille son propre disque et publie chaque matin son bilan de santé.


## Slide 19 — Le pipeline de revue — graphe d'état LangGraph
*(≈ 55 s)*

Le cœur du système est un graphe d'état à neuf nœuds. Suivons une Pull Request. [clics] Le webhook est reçu, vérifié et dédupliqué ; le dépôt est cloné et le diff généré localement avec quinze lignes de contexte. Le modèle 7B classifie en cinq catégories. Le routage choisit les scanners : une PR de documentation saute l'analyse, un Dockerfile déclenche le scan d'image complet. Les scanners s'exécutent en parallèle, chacun isolé dans sa coroutine — si l'un échoue, le pipeline continue. Le 14B mène ensuite l'analyse combinée selon l'OWASP Top 10, sur un diff annoté de numéros de lignes. Le verdict est rendu, avec escalade Slack si le risque est élevé, puis la revue est publiée sur GitHub. Une optimisation a changé l'échelle : la fusion des deux appels du 14B en un seul a fait passer le pipeline de trente-cinquante minutes à quinze-vingt-cinq.


## Slide 20 — Fiabilité — anti-hallucination et deux modèles
*(≈ 45 s)*

Reste la question légitime : peut-on faire confiance à un modèle de langage ? La réponse tient en six couches de protection. Trois agissent sur le modèle : température à zéro, fenêtre de contexte dimensionnée, génération plafonnée. Trois relèvent du contrôle applicatif : une garde qui force l'appel d'outil pour toute donnée en temps réel, des règles anti-hallucination dans le prompt, et l'obligation de ne citer que des valeurs présentes verbatim dans les observations. S'y ajoute, pour la revue de code, un parser dédié : il reconstruit l'ensemble exact des lignes valides du diff et écarte tout commentaire portant sur une ligne inexistante. Résultat : aucune erreur de ligne publiée sur GitHub.


## Slide 21 — 04
*(≈ 5 s)*

Passons à la réalisation et aux résultats.


## Slide 22 — Environnement de travail
*(≈ 30 s)*

Le terrain d'exécution est volontairement contraint : un VPS de production de douze cœurs Haswell, quarante-cinq giga-octets de mémoire, et sans GPU — c'est le prix de la confidentialité, et nous l'assumons. Cette contrainte a imposé un vrai travail de tuning : flash attention et quantisation du cache KV pour tenir le modèle 14B en mémoire. La pile logicielle est intégralement open source : Docker, Python, FastAPI, LangGraph, PostgreSQL, Redis et les cinq scanners.


## Slide 23 — Défense en profondeur — cinq scanners et un LLM
*(≈ 40 s)*

La détection suit une logique de défense en profondeur. Chaque scanner couvre une classe de risque — les CVE pour Trivy, les secrets pour Gitleaks, le code applicatif pour Semgrep, l'infrastructure pour Checkov, les dépendances pour OSV-Scanner — et le modèle consolide l'ensemble en une revue unique. Les deux niveaux se complètent réellement : sur la PR de démonstration, c'est le modèle qui a détecté des secrets en dur que Gitleaks n'avait pas signalés. Et les findings des scanners, eux, sont déterministes : ils sont persistés en base quel que soit le texte produit par le modèle.


## Slide 24 — Démonstration — Pull Request #18
*(≈ 50 s)*

Voici la démonstration, sur la Pull Request numéro dix-huit : un module bancaire en PHP contenant cinq vulnérabilités types — injection SQL, secrets en dur, path traversal, injection de commande et hachage MD5. À l'écran, la revue publiée par l'agent défile : l'analyse de chaque faille, puis les recommandations. [clic] Le verdict tombe : BLOCK. Cinq commentaires inline, chacun avec une suggestion de correction applicable en un clic depuis GitHub, et le statut de commit passe en échec : la fusion est techniquement bloquée tant que les corrections ne sont pas poussées. Durée totale pour cette revue : une quinzaine de minutes, notification Slack comprise.


## Slide 25 — 5 / 5
*(≈ 40 s)*

Le tableau résume le passage du processus manuel à l'agent : un délai divisé par près de cent ; une couverture OWASP systématique là où elle dépendait du relecteur ; un gate effectif là où rien ne bloquait ; et une traçabilité complète en base de données. Sur le jeu contrôlé, l'agent obtient cinq sur cinq, sans faux positif dans le fichier modifié. Au-delà de la démonstration, huit revues réelles sont persistées en base : les verdicts suivent le risque — REQUEST_CHANGES sur les PR de risque moyen, BLOCK sur les PR à risque élevé.


## Slide 26 — Supervision complète du VPS
*(≈ 40 s)*

L'agent voit l'intégralité du VPS : vingt-huit métriques personnalisées, quinze règles d'alerte organisées en cinq groupes, trois tableaux de bord Grafana. Quinze de ces métriques ont été ajoutées en fin de projet : la consommation de chaque conteneur — obtenue en interrogeant directement le socket Docker, après l'échec de cAdvisor sur notre version de Docker — et une télémétrie comparative des deux moteurs d'inférence. Cette supervision n'est pas décorative : elle a révélé un AlertManager silencieusement hors service depuis le déploiement initial, et une panne de VictoriaMetrics restée neuf jours invisible.


## Slide 27 — Assistant conversationnel et opérations autonomes
*(≈ 40 s)*

Au-delà de la revue, un assistant conversationnel doté de dix-neuf outils permet d'interroger l'infrastructure en langage naturel : l'état des conteneurs, les métriques Prometheus, et jusqu'à la base de connaissances sécurité, que l'on peut consulter sans écrire de SQL. À chaque question portant sur une donnée réelle, l'agent invoque l'outil correspondant et répond avec la valeur mesurée — jamais inventée. Il s'auto-exploite par ailleurs : un gardien disque vérifie l'occupation toutes les trente minutes et nettoie automatiquement au-delà de quatre-vingt-dix pour cent, et un bilan de santé complet est publié chaque matin sur Slack.


## Slide 28 — 0 → 51
*(≈ 35 s)*

L'épisode le plus révélateur du projet : la télémétrie a mis en évidence un bug du modèle Phi-4, qui renvoyait zéro token alors que la requête se terminait sans aucune erreur journalisée. La cause était un template de conversation mal formé, qui présentait au modèle une conversation déjà close. Le correctif a été aligné sur la configuration officielle du modèle, puis vérifié : de zéro à cinquante et un tokens. Le système a donc détecté une panne invisible aux journaux — c'est, je crois, la meilleure preuve qu'il se surveille lui-même.


## Slide 29 — Tests et validation de la plateforme
*(≈ 35 s)*

La validation finale a couvert les mécanismes critiques. Un webhook à la signature invalide est rejeté avant tout traitement. Un webhook dupliqué est ignoré silencieusement. En cas d'indisponibilité du modèle, le circuit breaker s'ouvre après trois échecs et une classification de repli par extensions de fichiers prend le relais : le pipeline ne s'arrête pas. Le gardien disque déclenche le nettoyage et le notifie sur Slack. Au total, une checklist de quatorze vérifications de bout en bout a été intégralement validée avant la livraison.


## Slide 30 — 05
*(≈ 5 s)*

J'en viens à la conclusion.


## Slide 31 — Limites et perspectives
*(≈ 50 s)*

Trois limites assumées. L'inférence sur CPU borne la revue à quinze-vingt-cinq minutes — environ trois tokens par seconde. Le durcissement réseau reste à compléter : des ports hôte à refermer, le passage à HTTPS, la sauvegarde quotidienne de la base. Et le verdict repose encore sur le jugement du modèle ; le faire reposer sur les findings déterministes des scanners le mettrait à l'abri d'une injection d'instructions dans le code soumis. Trois perspectives. La migration GPU — environ trois mille euros, dans l'enveloppe de la DSI — ramènerait chaque revue à deux-cinq minutes, sans toucher ni à l'architecture ni à la confidentialité. Le passage à l'échelle de l'ensemble des dépôts de la banque. Et un tableau de bord de risque alimenté par les revues accumulées, destiné au RSSI.


## Slide 32 — Un agent IA agentique, déployé en production à la BTE,
*(≈ 30 s)*

En conclusion : parti d'un VPS vierge, ce projet livre un agent d'intelligence artificielle complet, déployé en production à la BTE, qui sécurise chaque Pull Request sans qu'aucun code ne quitte la banque. La plateforme est remise à la banque et constitue un socle concret pour sa transformation DevSecOps. Je vous remercie de votre attention et me tiens à votre disposition pour répondre à vos questions.


---
## Conseils de répétition

- **[clic]** dans le texte = animation à déclencher (slides 7, 18, 19, 24 : un clic par élément).
- Répéter chronomètre en main, **trois fois minimum** ; si le créneau est de 15 minutes,
  compresser en priorité les slides 5, 13, 19 et 31 (les plus denses).
- Sur la slide 24 (démonstration), laisser le GIF boucler pendant la narration ; le clic final
  révèle le badge BLOCK.
- Les chiffres cités (80 %, 43 %, 22 %, 52 %, 5/5, 28 métriques, 15 règles, 19 outils) sont
  ceux du rapport : les connaître par cœur, le jury les reprendra en questions.
- Ne pas lire les slides : le texte ci-dessus est la narration, la slide est le support visuel.
- Boire un verre d'eau avant ; regarder le jury, pas l'écran.
