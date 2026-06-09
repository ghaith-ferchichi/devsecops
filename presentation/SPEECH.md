# Discours de soutenance — BTE Security AI Agent

> Généré depuis les **notes orateur** du `.pptx` (mode Présentateur de PowerPoint
> les affiche automatiquement). Régénérer après toute modification :
> `python3 build_pptx_modern.py` puis ce script.

**Durée totale estimée : ≈ 15 min 15 s** (répéter pour viser ~16:30 ; marge incluse).

## Minutage

| # | Slide | Temps |
|---|-------|-------|
| 1 | UNIVERSITÉ DE TUNIS EL MANAR · INSTITUT SUPÉRIEUR D' | 30 s |
| 2 | PLAN | 20 s |
| 3 | INTRODUCTION | 30 s |
| 4 | Contexte | 5 s |
| 5 | Organisme d'accueil et étude de l'existant | 40 s |
| 6 | Problématique | 30 s |
| 7 | Objectifs et contribution | 40 s |
| 8 | Solution proposée (TO-BE) | 30 s |
| 9 | Méthodologie de travail | 30 s |
| 10 | État de l'art | 5 s |
| 11 | DevSecOps et approche shift-left | 25 s |
| 12 | Spécification des besoins | 35 s |
| 13 | Choix des modèles LLM — benchmark sur le matériel ci | 40 s |
| 14 | Technologies retenues | 30 s |
| 15 | Positionnement par rapport aux solutions existantes | 30 s |
| 16 | Conception | 5 s |
| 17 | Architecture globale de la solution | 30 s |
| 18 | Un agent autonome, et non un simple appel LLM | 40 s |
| 19 | Le pipeline de revue — graphe d'état LangGraph | 45 s |
| 20 | Fiabilité — anti-hallucination et deux modèles | 35 s |
| 21 | Réalisation | 5 s |
| 22 | Environnement de travail | 25 s |
| 23 | Défense en profondeur — cinq scanners et un LLM | 35 s |
| 24 | Démonstration — Pull Request #18 | 45 s |
| 25 | Bénéfices et résultats | 35 s |
| 26 | Supervision complète du VPS | 30 s |
| 27 | Assistant conversationnel et opérations autonomes | 30 s |
| 28 | Détection autonome de ses propres pannes | 30 s |
| 29 | Tests et validation de la plateforme | 30 s |
| 30 | Conclusion | 5 s |
| 31 | Limites et perspectives | 40 s |
| 32 | CONCLUSION | 30 s |

---
## Texte intégral, slide par slide

## Slide 1 — UNIVERSITÉ DE TUNIS EL MANAR · INSTITUT SUPÉRIEUR D'INFORMATIQUE
*(≈ 30 s)*

Monsieur le Président du jury, Madame, Messieurs les membres du jury, bonjour. Je m'appelle Ghaith Ferchichi et j'ai l'honneur de vous présenter mon projet de fin d'études, réalisé au sein de la Banque de Tunisie et des Émirats, en vue de l'obtention du Diplôme National de Mastère Professionnel, spécialité Sécurité des Systèmes d'Information et des Infrastructures. Ce projet s'intitule BTE Security AI Agent : un agent d'intelligence artificielle pour la revue automatisée de sécurité du code.


## Slide 2 — PLAN
*(≈ 20 s)*

Mon exposé suit la structure du rapport, en cinq chapitres : le contexte général du projet ; l'état de l'art et les choix technologiques ; la conception de l'agent ; sa réalisation et ses résultats ; et enfin la conclusion et les perspectives.


## Slide 3 — INTRODUCTION
*(≈ 30 s)*

Pour situer l'enjeu : une seule injection SQL fusionnée dans une API de paiement peut compromettre l'intégrité du système d'information de la banque. Or, à la BTE, la revue de sécurité du code demeure entièrement manuelle : elle peut atteindre vingt-quatre heures, et sa qualité dépend de la disponibilité et de l'expertise du relecteur. C'est ce constat qui motive ce travail.


## Slide 4 — Contexte
*(≈ 5 s)*

Commençons par le contexte général.


## Slide 5 — Organisme d'accueil et étude de l'existant
*(≈ 40 s)*

La BTE est une banque universelle née d'un partenariat entre l'État tunisien et l'Abu Dhabi Investment Authority. Mon stage s'est déroulé au sein du pôle Sécurité de la Direction des Systèmes d'Information. Le processus actuel, que vous voyez à gauche, repose intégralement sur l'examen humain : le relecteur examine le diff dans GitHub, dépose ses commentaires, puis fusionne manuellement. Aucune analyse statique, aucun gate de pipeline n'est greffé sur ce cycle.


## Slide 6 — Problématique
*(≈ 30 s)*

Quatre limites en découlent. Un délai pouvant atteindre vingt-quatre heures, selon la disponibilité et l'expertise du relecteur. L'absence de tout blocage technique : une Pull Request vulnérable peut être fusionnée. Une qualité de revue variable. Et des angles morts : les secrets commités et les dépendances vulnérables échappent à l'œil humain.


## Slide 7 — Objectifs et contribution
*(≈ 40 s)*

Notre contribution tient en une phrase : un agent IA autonome qui revoit chaque Pull Request selon l'OWASP Top 10 en une quinzaine de minutes, publie les correctifs sur GitHub, et s'exécute intégralement en local — aucun code ne quitte la banque. [clic] De vingt-quatre heures à quinze minutes. [clic] Cinq vulnérabilités sur cinq détectées lors de la validation. [clic] Et zéro ligne de code ne sort du VPS.


## Slide 8 — Solution proposée (TO-BE)
*(≈ 30 s)*

Concrètement, voici le processus cible : GitHub émet un webhook signé ; l'agent classifie la Pull Request, exécute cinq scanners en parallèle, consolide leurs résultats avec un modèle de langage local, puis publie la revue, le score et le verdict. Et c'est ce verdict qui conditionne la fusion.


## Slide 9 — Méthodologie de travail
*(≈ 30 s)*

Le projet a été conduit selon la méthode Scrumban : la cadence de sprints de Scrum, la discipline de flux de Kanban avec un travail en cours limité à un. Dix sprints sur cinq mois. Chaque incident de production est devenu la carte prioritaire du sprint en cours — c'est ainsi qu'ont été absorbés l'urgence disque et la réécriture du parser de revue.


## Slide 10 — État de l'art
*(≈ 5 s)*

Passons à l'état de l'art et aux choix technologiques.


## Slide 11 — DevSecOps et approche shift-left
*(≈ 25 s)*

Le cadre conceptuel est le DevSecOps et son principe de shift-left : intégrer la sécurité au plus tôt du cycle, idéalement dès la Pull Request. Notre apport consiste à transformer le verdict de l'agent en un gate technique, qui conditionne réellement la fusion.


## Slide 12 — Spécification des besoins
*(≈ 35 s)*

Côté besoins fonctionnels : détecter les vulnérabilités, produire la revue OWASP, publier les commentaires, conditionner la fusion, et offrir un assistant d'exploitation. Côté non fonctionnel, la contrainte dominante est la confidentialité : l'inférence doit rester locale, conformément aux exigences de la Banque Centrale de Tunisie. S'y ajoutent la performance, la résilience et l'observabilité.


## Slide 13 — Choix des modèles LLM — benchmark sur le matériel cible
*(≈ 40 s)*

Le choix des modèles repose sur un banc d'essai mené sur notre propre matériel. Deux modèles ressortent : qwen2.5-coder 7B et 14B, à égalité de précision d'appel d'outils — quatre-vingts pour cent — le 7B étant nettement plus rapide. D'où une architecture à deux modèles : le 7B classifie en trente secondes, le 14B mène l'analyse approfondie. Un benchmark croisé a par ailleurs confirmé le choix d'Ollama : vingt-deux pour cent de débit de plus que LocalAI, sur un fichier de poids identique.


## Slide 14 — Technologies retenues
*(≈ 30 s)*

L'ensemble s'appuie sur trois briques : cinq scanners spécialisés, chacun couvrant une classe de risque ; deux modèles de langage locaux ; et l'orchestrateur LangGraph, retenu pour sa persistance d'état native. Les sorties des scanners sont nettoyées — moins cinquante-deux pour cent de tokens — avant transmission au modèle.


## Slide 15 — Positionnement par rapport aux solutions existantes
*(≈ 30 s)*

Aucune solution existante ne combine raisonnement par modèle de langage et inférence entièrement locale : CodeQL, Snyk et Copilot transmettent le code au cloud ; SonarQube reste auto-hébergeable mais sans explication en langage naturel. C'est notre différenciateur : rien ne sort du VPS de la banque.


## Slide 16 — Conception
*(≈ 5 s)*

Venons-en à la conception.


## Slide 17 — Architecture globale de la solution
*(≈ 30 s)*

La plateforme compte onze conteneurs organisés en quatre couches : la couche d'entrée, avec nginx qui valide les webhooks ; la couche IA — FastAPI, LangGraph et Ollama ; la couche données — PostgreSQL et Redis ; et la couche observabilité, sur laquelle je reviendrai.


## Slide 18 — Un agent autonome, et non un simple appel LLM
*(≈ 40 s)*

J'insiste sur ce point : il s'agit d'un agent, et non d'un simple appel à un modèle. Six capacités le démontrent. [clics] Il perçoit les événements GitHub ; il raisonne et route son graphe d'état ; il agit — commente, bloque, escalade ; il persiste son état et reprend après un redémarrage ; il manipule dix-neuf outils réels ; et il s'auto-exploite au quotidien.


## Slide 19 — Le pipeline de revue — graphe d'état LangGraph
*(≈ 45 s)*

Le cœur du système est un graphe d'état à neuf nœuds. Suivons une Pull Request. [clics] Réception et déduplication du webhook ; classification par le modèle 7B ; routage des scanners selon la nature des fichiers ; exécution parallèle des cinq scanners ; analyse combinée par le 14B selon l'OWASP Top 10 ; verdict ; publication sur GitHub. La fusion des deux appels du 14B en un seul a réduit la durée totale du pipeline de moitié.


## Slide 20 — Fiabilité — anti-hallucination et deux modèles
*(≈ 35 s)*

La question légitime : peut-on faire confiance à un modèle de langage ? Six couches de protection éliminent les hallucinations — température zéro, fenêtre de contexte maîtrisée, garde d'outils, et surtout un parser qui élimine tout commentaire portant sur une ligne inexistante du diff. C'est ce qui permet de publier sur GitHub sans aucune erreur de ligne.


## Slide 21 — Réalisation
*(≈ 5 s)*

Passons à la réalisation et aux résultats.


## Slide 22 — Environnement de travail
*(≈ 25 s)*

Le terrain d'exécution est volontairement contraint : un VPS de production de douze cœurs Haswell, quarante-cinq giga-octets de mémoire, et sans GPU. La pile logicielle est intégralement open source : Docker, Python, FastAPI, LangGraph, PostgreSQL, Redis et les cinq scanners.


## Slide 23 — Défense en profondeur — cinq scanners et un LLM
*(≈ 35 s)*

La détection suit une logique de défense en profondeur : chaque scanner couvre une classe de risque — CVE, secrets, code applicatif, infrastructure, dépendances — et le modèle consolide l'ensemble. Les deux se complètent : sur la PR de démonstration, le modèle a détecté des secrets en dur que Gitleaks n'avait pas signalés.


## Slide 24 — Démonstration — Pull Request #18
*(≈ 45 s)*

Voici la démonstration, sur la Pull Request numéro dix-huit : un module bancaire contenant cinq vulnérabilités types. À l'écran, la revue publiée par l'agent défile jusqu'au verdict. [clic] BLOCK. Cinq commentaires inline, chacun avec une suggestion applicable en un clic, et le statut de commit passe en échec : la fusion est techniquement bloquée.


## Slide 25 — Bénéfices et résultats
*(≈ 35 s)*

Le tableau résume le passage du processus manuel à l'agent : un délai divisé par près de cent ; une couverture OWASP systématique ; un gate effectif ; et la confidentialité garantie. Sur le jeu contrôlé, l'agent obtient cinq sur cinq, complétés par huit revues réelles persistées en base.


## Slide 26 — Supervision complète du VPS
*(≈ 30 s)*

L'agent voit l'intégralité du VPS : vingt-huit métriques, quinze règles d'alerte, trois tableaux de bord. Cette supervision n'est pas décorative : elle a permis de détecter un AlertManager silencieusement hors service et une panne de VictoriaMetrics de neuf jours.


## Slide 27 — Assistant conversationnel et opérations autonomes
*(≈ 30 s)*

Au-delà de la revue, un assistant conversationnel doté de dix-neuf outils permet d'interroger l'infrastructure en langage naturel : l'agent invoque l'outil réel et répond avec la valeur mesurée — jamais inventée. Et il s'auto-exploite : scheduler autonome, health digest quotidien sur Slack, gardien disque auto-réparateur.


## Slide 28 — Détection autonome de ses propres pannes
*(≈ 30 s)*

L'épisode le plus révélateur : la télémétrie a mis en évidence un bug du modèle Phi-4, qui renvoyait zéro token sans aucune erreur journalisée. Le système a donc détecté une panne invisible aux journaux — diagnostiquée, corrigée, puis vérifiée. C'est, je crois, la meilleure preuve qu'il s'agit d'un système qui se surveille lui-même.


## Slide 29 — Tests et validation de la plateforme
*(≈ 30 s)*

La validation finale a couvert les mécanismes critiques : rejet des signatures invalides, déduplication des webhooks, circuit breaker avec repli en cas d'indisponibilité du modèle, et déclenchement du gardien disque. Une checklist de quatorze vérifications de bout en bout a été intégralement validée avant la livraison.


## Slide 30 — Conclusion
*(≈ 5 s)*

J'en viens à la conclusion.


## Slide 31 — Limites et perspectives
*(≈ 40 s)*

Trois limites assumées : l'inférence sur CPU, qui borne la revue à quinze-vingt-cinq minutes ; un durcissement réseau à compléter ; et un corpus d'évaluation restreint. Trois perspectives : la migration GPU — environ trois mille euros — ramènerait chaque revue à deux à cinq minutes ; le passage à l'échelle de l'ensemble des dépôts de la banque ; et un tableau de bord de risque destiné au RSSI.


## Slide 32 — CONCLUSION
*(≈ 30 s)*

En conclusion : un agent IA agentique, déployé en production à la BTE, qui sécurise chaque Pull Request sans qu'aucun code ne quitte la banque. La plateforme est remise à la banque et constitue un socle concret pour sa transformation DevSecOps. Je vous remercie de votre attention et me tiens à votre disposition pour répondre à vos questions.


---
## Conseils de répétition

- **[clic]** dans le texte = animation à déclencher (slides 7, 18, 19, 24 : un clic par élément).
- Répéter chronomètre en main, **trois fois minimum** ; viser 16:30 pour garder une marge.
- Sur la slide 24 (démonstration), laisser le GIF boucler pendant la narration ; le clic final révèle le badge BLOCK.
- Ne pas lire les slides : le texte ci-dessus est la narration, la slide est le support visuel.
- Boire un verre d'eau avant ; regarder le jury, pas l'écran.