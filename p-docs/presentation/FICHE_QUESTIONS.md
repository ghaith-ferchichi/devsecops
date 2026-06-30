# Fiche défense — questions du jury (le moment où on gagne des points)

> La soutenance se joue ici. Le discours montre que tu sais présenter ; **les réponses montrent que tu maîtrises**.
> Règle : **valide la question** (« Très bonne question »), **réponds en une phrase d'ancrage**, puis **développe 2-3 points**, puis **stop**. Ne meuble pas. Si tu ne sais pas : « Je ne l'ai pas traité, voici comment je l'aborderais… » — jamais d'invention (c'est exactement ce que ton agent ne fait pas !).

---

## A. Les 3 questions PIÈGES (prépare-les par cœur)

### A1. « Le diff est une entrée non fiable. Et l'injection de prompt ? Un attaquant peut écrire dans son code un commentaire qui manipule le LLM. »
> **C'EST LA question d'un jury sécurité. Si tu la gères bien, tu as gagné.**
- **Ancre** : « Le diff est traité comme une donnée hostile, jamais comme une instruction. »
- Trois lignes de défense :
  1. **Les findings des scanners sont déterministes** — Trivy, Semgrep, Gitleaks ne lisent pas de langage naturel, on ne peut pas les « convaincre ». Ils sont persistés en base **quoi que dise le LLM**.
  2. **Le prompt système isole le contenu du diff** comme données à analyser, avec des règles anti-hallucination et l'interdiction de citer une valeur absente des observations.
  3. **Le LLM ne décide pas seul du gate** : un diff hostile peut au pire dégrader le *texte* de la revue, pas effacer un finding scanner ni forcer un APPROVE.
- **Honnêteté** : « Le durcissement de l'ancrage du verdict sur les findings déterministes est explicitement dans mon plan de durcissement — je l'assume comme limite. »

### A2. « Vous validez sur UNE PR (7/7) et 8 revues réelles. C'est très peu. Comment prouvez-vous que ça marche ? »
- **Ancre** : « Vous avez raison, le corpus est restreint, et je l'assume comme limite n°2. »
- Mais : 
  1. La PR de test est **conçue pour couvrir l'OWASP Top 10** (7 classes de vulnérabilités + 3 secrets) — c'est une validation *qualitative* du pipeline de bout en bout, pas une mesure statistique.
  2. Les **8 revues réelles** montrent que les verdicts suivent le risque en conditions de production.
  3. La **rigueur est dans la méthode** : 14 vérifications de bout en bout sur les mécanismes critiques (HMAC, dédup, circuit breaker, gardien disque).
- **Ne te défends pas trop** : reconnais-le, c'est une vraie limite d'un PFE de 5 mois. Un jury respecte la lucidité.

### A3. « 15 à 25 minutes par revue, c'est lent. Est-ce utilisable en vrai ? »
- **Ancre** : « C'est le prix assumé de la confidentialité — pas une fatalité technique. »
  1. La revue est **asynchrone** : le dev n'attend pas, il continue à travailler ; le gate se pose quand c'est prêt.
  2. C'est le coût du **CPU sans GPU**, contrainte que j'ai choisie pour que rien ne sorte de la banque.
  3. **Perspective chiffrée** : une carte GPU à ~3000 € (dans l'enveloppe DCIO) → 30-50 tok/s → **2 à 5 minutes**, sans toucher à l'architecture.

---

## B. Questions de CONCEPTION (« pourquoi ce choix ? »)

**« Pourquoi un LLM ? Les 5 scanners ne suffisent-ils pas ? »**
→ Les scanners **détectent**, ils n'**expliquent** pas et ne **priorisent** pas. Le 14B consolide 5 sorties hétérogènes en **une revue unique OWASP**, priorisée, avec **une suggestion de correction par point**, et un **verdict** exploitable comme gate. Sans lui : 200+ findings bruts que personne ne lit.

**« Pourquoi qwen2.5-coder et pas un modèle plus gros / GPT ? »**
→ Contrainte = **inférence locale sur CPU**. J'ai benchmarké sur le **matériel cible** avec le prompt système réel : llama3.2:3b saturé, granite incompatible outils. Le 14B tient en mémoire (quantisation + flash attention) à 80 % de précision d'appel d'outils. GPT = cloud = exclu d'office.

**« Pourquoi deux modèles et pas un seul ? »**
→ **Économie de ressources** : classifier est une tâche simple → le 7B (rapide, ~30 s) ; analyser est complexe → le 14B. Faire tout au 14B = plus lent pour rien sur les PR triviales (doc, config).

**« Pourquoi LangGraph et pas Celery / Prefect / un simple script ? »**
→ **La persistance d'état native dans PostgreSQL** : un pipeline de 20 min **survit au redémarrage du conteneur** et reprend au nœud exact. Avec un script, un crash = on recommence tout. C'est ce qui fait de l'outil un **agent** et non un job.

**« Qu'est-ce qui fait que c'est un “agent” et pas un pipeline ? »**
→ Six capacités (slide manifeste) : il **perçoit** (webhooks/métriques), **raisonne** (classe + route), **agit** (commente/bloque/escalade), **persiste** (checkpoints), **utilise 19 outils**, et **s'auto-exploite** (gardien disque, health digest). Un pipeline ne décide pas de sa propre route ni ne se répare.

---

## C. Questions de SÉCURITÉ (le jury va creuser, c'est sa spécialité)

**« Et si le secret du webhook HMAC fuite ? »**
→ HMAC-SHA256 vérifie l'**authenticité + intégrité** ; signature invalide = rejet 403 avant tout traitement. Le secret est en variable d'environnement, jamais dans le code (Gitleaks le vérifierait lui-même). Rotation possible. **nginx est le seul point exposé** ; Ollama et la base ne sont accessibles que depuis le réseau Docker interne.

**« L'agent a 19 outils et accès au socket Docker. C'est une surface d'attaque énorme. »**
→ Vrai, et c'est pourquoi **il n'est exposé à personne** : pas d'API publique d'administration, tout passe par nginx authentifié. Les outils sont en **lecture/diagnostic** majoritairement ; les actions (nettoyage disque) sont bornées et notifiées sur Slack. Durcissement supplémentaire = travail futur.

**« Le LLM peut-il halluciner un numéro de ligne et commenter au mauvais endroit ? »**
→ Non : un **parser dédié** écarte tout commentaire visant une ligne **absente du diff** avant publication. **Résultat mesuré : zéro erreur de ligne publiée sur GitHub.**

**« Faux négatifs : une vraie faille qu'il rate ? »**
→ Possible — aucun outil n'est parfait. La **défense en profondeur** réduit le risque : 5 moteurs déterministes + raisonnement LLM se recoupent. Et le verdict est un **filet supplémentaire**, pas un remplacement du relecteur humain qui reste dans la boucle pour la fusion.

---

## D. Questions de PORTÉE / VALEUR

**« Combien ça a coûté ? Le ROI ? »**
→ Coût matériel : **0 € de plus** (VPS existant, pile 100 % open source). Gain : délai de revue **÷ ~100**, couverture OWASP systématique, traçabilité complète. Le seul investissement futur optionnel = ~3000 € de GPU.

**« Passage à l'échelle sur tous les dépôts de la banque ? »**
→ Architecture déjà multi-dépôt (le webhook porte le dépôt). À l'échelle : file d'attente + éventuellement GPU pour absorber le débit. C'est la **perspective n°2**.

**« Qui maintient l'agent après votre départ ? »**
→ Pile **standard et documentée** (Docker, FastAPI, Postgres, Ollama), **observabilité complète** (28 métriques, 15 alertes, 3 dashboards) qui rend les pannes visibles, et **health digest quotidien**. La plateforme est conçue pour être **opérée**, pas seulement démontrée.

**« En quoi c'est différent de SonarQube / GitHub Advanced Security ? »**
→ Aucun ne combine **raisonnement LLM** + **inférence 100 % locale**. SonarQube = statique sans explication ; Snyk/Copilot = code envoyé au cloud (inacceptable en banque). Mon apport unit les deux.

**« Vous démontrez sur GitHub, mais la banque utilise GitLab. Est-ce portable ? »** ⭐
→ Oui — et c'est assumé. **GitHub a servi à simuler les scénarios** de Pull Request pour le PFE. L'architecture est **pilotée par webhook et découplée du fournisseur Git** : porter vers GitLab se limite à deux adaptateurs — la **vérification de signature du webhook** et le **client API** (publier la revue, poser le statut sur la merge request). Le cœur — **5 scanners, graphe LangGraph, analyse LLM, persistance PostgreSQL** — ne change pas une ligne. C'est un point explicite de l'industrialisation.

---

## E. Réponses passe-partout (à dégainer sous pression)

- **Tu ne sais pas** → « Je n'ai pas couvert ce point dans le périmètre du stage. Voici comment je l'aborderais : … » *(propose une piste, ne bluffe pas).*
- **Question hostile / sceptique** → reformule calmement : « Si je comprends bien, vous demandez si … ? » → gagne 3 s + montre l'écoute.
- **On t'attaque une limite** → **donne-leur raison d'abord** : « C'est exact, et je l'ai identifié comme limite. » → tu désamorces, tu parais lucide.
- **Question hors-sujet / trop large** → ramène à ton fil : « Dans le cadre de ce projet, … »

---

## F. Le mot de la fin (si on te demande « un dernier mot ? »)
> « Parti d'un VPS vierge, j'ai livré un agent IA complet, en production, qui sécurise chaque Pull Request sans qu'aucun code ne quitte la banque. Au-delà du code, c'est un socle concret pour la transformation DevSecOps de la BTE. »
</content>
