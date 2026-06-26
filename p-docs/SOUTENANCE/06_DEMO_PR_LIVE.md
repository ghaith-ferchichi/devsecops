# 06 — Démo live : une revue de Pull Request de bout en bout

> **But de ce document** : dérouler, étape par étape, une **vraie** revue de PR pendant la réunion, pour que la rapporteuse **voie ce qui se passe** à chaque instant. Chaque étape suit le même format :
>
> **① Ce que tu dis** → **② La commande** → **③ Ce qui apparaît (sortie réelle)** → **④ Ce que ça prouve**.
>
> Ce scénario a été **exécuté et vérifié** sur le VPS (PR #19, dépôt `GhaiethFerchichi/Vunl-application`). Les sorties ci-dessous sont les vraies sorties observées. Tu peux le rejouer à l'identique.

---

## Vue d'ensemble — le trajet d'une PR

Avant de taper quoi que ce soit, poser le décor à l'oral :

> « Quand un développeur ouvre une Pull Request, GitHub envoie un **webhook** signé à l'agent. L'agent clone le code, calcule le **diff**, classe la PR, lance **5 scanners** de sécurité en parallèle, demande à un **LLM local** une revue ligne par ligne, puis **publie le verdict et les commentaires inline** directement sur la PR. Tout est local, rien ne sort vers le cloud. »

Le pipeline en 9 nœuds (graphe LangGraph) :

```
webhook → intake → classify → scan → analyze → escalate? → report
          (clone)  (7B)      (5 scanners) (14B)  (Slack si besoin) (GitHub + Postgres)
```

> ⚠️ **Durée réelle** : ~15–20 min sur CPU (ici ~17 min). **Stratégie de réunion** : lancer la PR **en début** de séance, montrer le webhook arriver et les premiers nœuds défiler, puis **passer à autre chose** (Postgres, Grafana, le code) et **revenir à la fin** montrer le résultat publié. OU montrer une PR **déjà traitée** (PR #19) dont les commentaires sont déjà sur GitHub.

---

## 0. Préparation (avant de partager l'écran)

### ① Ce que tu dis
> « Je prépare deux terminaux : un pour déclencher, un pour suivre les logs en direct. »

### ② Les commandes
```bash
cd /opt/devsecops
clear
```

**Réchauffer le modèle** (étape critique — sinon le premier appel LLM est lent à froid) :
```bash
docker exec ollama ollama run qwen2.5-coder:7b "Réponds juste: OK"
docker exec ollama ollama ps
```

### ③ Ce qui apparaît
```
NAME                ID              SIZE      PROCESSOR    CONTEXT    UNTIL
qwen2.5-coder:7b    dae161e27b0e    4.5 GB    100% CPU     4096       20 minutes from now
```

### ④ Ce que ça prouve
Le modèle est **chargé en RAM** et restera chaud ~20 min. La classification de la PR sera rapide.

---

## 1. Le code vulnérable qu'on va soumettre

### ① Ce que tu dis
> « Voici le fichier que je vais soumettre dans une PR. C'est un module de virement bancaire avec **8 vulnérabilités volontaires** : injection SQL, injection de commande, SSRF, désérialisation, XSS, crypto faible, secrets en dur. C'est exactement le genre de code qu'un agent de sécurité doit bloquer. »

### ② La commande
```bash
cat test-targets/Vunl-application/wire_transfer.php
```

### ③ Ce qui apparaît (extrait)
```php
// --- Secrets en dur (Gitleaks) ---
$STRIPE_SECRET_KEY = "sk_test_51H8xY2...";
$DB_DSN = "mysql:host=10.0.0.5;dbname=core_banking;user=root;password=Pr0d_R00t_2026";

// --- SQL injection ---
$sql = "SELECT balance FROM accounts WHERE id = " . $_GET['account_id'];

// --- Command injection ---
$cmd = "wkhtmltopdf /statements/" . $_GET['account_id'] . ".html /out.pdf";
return shell_exec($cmd);

// --- SSRF / désérialisation / XSS / MD5 ... (etc.)
```

### ④ Ce que ça prouve
Le banc de test est **réaliste** : ce ne sont pas des erreurs triviales, ce sont les vulnérabilités du **OWASP Top 10** appliquées à un contexte bancaire.

---

## 2. Déclencher la revue : ouvrir la PR

### ① Ce que tu dis
> « Je pousse la branche et j'ouvre une Pull Request. C'est l'action normale d'un développeur — à partir de là, l'agent prend le relais tout seul. »

### ② Les commandes
```bash
cd test-targets/Vunl-application
git checkout -b demo-soutenance main
# (le fichier wire_transfer.php est ajouté)
git add wire_transfer.php
git commit -m "feat: module de virement bancaire"
git push -u origin demo-soutenance
```
Puis ouvrir la PR (sur GitHub dans le navigateur, bouton **« Compare & pull request »**, ou via l'API).

### ③ Ce qui apparaît
GitHub crée la PR (ici **#19**) et **envoie immédiatement le webhook** au VPS.

### ④ Ce que ça prouve
Aucune intervention manuelle côté sécurité : le simple fait d'**ouvrir la PR** lance toute la chaîne.

> 💡 **Note technique à mentionner si on demande** : GitHub a une *push protection* qui bloque les clés d'API « live » (ex. `sk_live_…`). On utilise donc des clés de **test** (`sk_test_…`) : elles passent la protection de GitHub mais restent détectées par **Gitleaks** côté agent. C'est volontaire pour la démo.

---

## 3. Le webhook arrive — suivre les logs en direct

### ① Ce que tu dis
> « Dans le deuxième terminal, je suis les logs de l'agent en temps réel. On va voir le webhook arriver, la signature HMAC validée, puis chaque nœud du pipeline s'exécuter. »

### ② La commande
```bash
docker logs devsecops-agent -f
```
*(ou pour ne voir que la dernière minute : `docker logs devsecops-agent --since 90s`)*

### ③ Ce qui apparaît (sortie réelle)
```
webhook_received        action=opened  github_event=pull_request
webhook_dispatched      pr=19          task_id=01eb5b26-...
dispatching_event       event_type=pull_request
intake_start            pr=19          repo=GhaiethFerchichi/Vunl-application
posting_pr_comment      body_len=54    pr=19          → "Security review in progress..."
cloning_repo            branch=demo-soutenance
clone_success
local_diff_generated    length=1782
intake_complete         diff_len=1782  files=1  has_dockerfile=False
classify_start          pr=19
```

### ④ Ce que ça prouve
- `webhook_received` + `202 Accepted` : le webhook est reçu et **sa signature HMAC est validée** (sinon `403`).
- `posting_pr_comment` : l'agent poste **tout de suite** un commentaire « revue en cours » sur la PR (feedback immédiat au développeur).
- `cloning_repo` → `local_diff_generated` : il **clone** le dépôt et calcule le **diff** (1782 caractères, 1 fichier).
- `classify_start` : il passe à la classification.

---

## 4. Classification de la PR (LLM 7B)

### ① Ce que tu dis
> « Premier appel au modèle : il lit le diff et classe la PR. Ça évite de scanner pour rien : une PR de documentation n'a pas besoin du même traitement qu'une PR de code. »

### ② (déjà dans les logs `-f`)

### ③ Ce qui apparaît
```
classify_complete   classification=feature   risk_hint=medium   duration=35.0s   pr=19
```

### ④ Ce que ça prouve
Le modèle **7B** classe la PR en **35 secondes** : type `feature`, risque a priori `medium`. Le routage conditionnel du graphe enverra donc cette PR au scan complet.

---

## 5. Les scanners de sécurité (5 outils en parallèle)

### ① Ce que tu dis
> « Maintenant l'analyse statique : l'agent lance plusieurs scanners en parallèle. **Trivy** pour les dépendances et les misconfigs, **Gitleaks** pour les secrets, **Semgrep** pour les patterns de code vulnérables. Chacun écrit son rapport JSON. »

### ② (toujours les logs `-f`)

### ③ Ce qui apparaît (sortie réelle)
```
scan_fs_start         pr=19
scanning_filesystem   service=trivy     severity=CRITICAL,HIGH,MEDIUM
scanning_secrets      service=gitleaks
scanning_sast         service=semgrep
scan_complete         scanner=gitleaks  duration=0.7s
trivy_parsed          summary={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
scan_complete         scanner=trivy_fs  duration=5.5s
semgrep_parsed        count=42          summary={'ERROR':35,'WARNING':7,'INFO':0}
scan_complete         scanner=semgrep   duration=6.2s
scan_fs_complete      scanners=['trivy_fs','gitleaks','semgrep']
```

### ④ Ce que ça prouve
- **Semgrep trouve 42 findings** (35 `ERROR` + 7 `WARNING`) — il a détecté toutes nos vulnérabilités de code.
- **Gitleaks** s'exécute en 0.7 s et repère les secrets en dur.
- **Trivy** retourne 0 (normal : pas de fichier de dépendances ici, juste du PHP) — ce qui montre que **l'agent ne fabrique rien** : s'il n'y a pas de dépendances, il ne déclare pas de fausse vulnérabilité.
- Les scanners tournent **en parallèle** et chaque résultat est **sauvegardé en base** (`scan_result_saved`).

---

## 6. La revue par le LLM (modèle 14B)

### ① Ce que tu dis
> « Les scanners donnent des findings bruts. L'agent les transmet maintenant au modèle **14B**, plus puissant, qui rédige une revue **ligne par ligne** en langage naturel, avec une explication et une recommandation pour chaque problème. C'est l'étape la plus longue car le modèle est plus gros et on est en CPU. »

### ② Vérifier que le 14B s'est bien chargé
```bash
docker exec ollama ollama ps
```

### ③ Ce qui apparaît
```
NAME                 ID              SIZE      PROCESSOR    CONTEXT    UNTIL
qwen2.5-coder:14b    9ec8897f747e    9.8 GB    100% CPU     12288      ...
```
Puis, en fin de pipeline (logs) : `analyze_review_complete` → `report`.

### ④ Ce que ça prouve
L'agent utilise **deux modèles** selon la tâche : le **7B** rapide pour classer/chatter, le **14B** pour l'analyse de fond. C'est un choix d'architecture assumé pour un VPS **CPU-only**.

---

## 7. Le résultat publié sur GitHub

### ① Ce que tu dis
> « Le pipeline se termine en publiant directement sur la PR : un commentaire de verdict global, et **un commentaire inline sur chaque ligne** concernée. C'est ce que le développeur voit dans son flux GitHub habituel. »

### ② Aller sur la PR dans le navigateur
`https://github.com/GhaiethFerchichi/Vunl-application/pull/19` → onglet **Files changed**.

### ③ Ce qui apparaît (sortie réelle — 8 commentaires inline)
```
wire_transfer.php:5   🟠 [HIGH] Hardcoded Secrets — API keys / DB creds in source
wire_transfer.php:12  🟠 [HIGH] SQL Injection — use prepared statements
wire_transfer.php:18  🟠 [HIGH] Command Injection — validate/sanitize inputs
wire_transfer.php:24  🟠 [HIGH] SSRF — validate the URL before fetching
wire_transfer.php:30  🟠 [HIGH] Insecure Deserialization — use JSON + validation
wire_transfer.php:35  🟠 [HIGH] Reflected XSS — escape output
wire_transfer.php:40  🟡 [MEDIUM] Weak Crypto — MD5 is broken, use bcrypt/argon2
wire_transfer.php:45  🟠 [HIGH] Insecure Password Handling — never pass secrets in URL
```
Et le commentaire de synthèse :
```
## SECURITY AI AGENT — Security Review
Risk: HIGH | Verdict: BLOCK | Classification: feature
```

### ④ Ce que ça prouve
L'agent **bloque** la PR (`BLOCK`) avec un score `HIGH`, et donne au développeur des commentaires **précis, localisés et actionnables** — exactement comme un relecteur humain senior, mais en quelques minutes et sans intervention.

---

## 8. La trace en base de données (PostgreSQL)

### ① Ce que tu dis
> « Tout est aussi persisté en base. L'agent garde une mémoire de chaque revue : c'est ce qui lui permet de construire des profils de dépôts et de suivre l'évolution du risque dans le temps. »

### ② Les commandes
```bash
docker exec -it postgres psql -U devsecops -d devsecops_db
```
```sql
SELECT pr_number, classification, risk_score, verdict, duration_ms
FROM pr_reviews WHERE pr_number = 19;

SELECT scan_type, summary
FROM scan_results
WHERE repo_full_name = 'GhaiethFerchichi/Vunl-application'
ORDER BY created_at DESC LIMIT 3;
\q
```

### ③ Ce qui apparaît (sortie réelle)
```
 pr_number | classification | risk_score | verdict | duration_ms
-----------+----------------+------------+---------+-------------
        19 | feature        | HIGH       | BLOCK   |     1030554

 scan_type | summary
-----------+-----------------------------------------------
 semgrep   | {"ERROR": 35, "WARNING": 7, "INFO": 0}
 trivy_fs  | {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, ...}
```

### ④ Ce que ça prouve
La revue (verdict, score, durée ~17 min, résumé des scans) est **enregistrée durablement**. La base est la **mémoire long terme** de l'agent — et le **checkpointer** LangGraph qui permet de reprendre un workflow mis en pause.

---

## 9. Récapitulatif — la phrase de conclusion

> « En résumé : un développeur ouvre une PR, et **sans aucune action de ma part**, l'agent l'a clonée, classée, scannée avec 5 outils, analysée par deux LLM locaux, puis a publié un verdict **BLOCK** avec 8 commentaires précis sur GitHub, et tout est tracé en base. C'est un relecteur de sécurité autonome qui tourne **entièrement sur notre VPS**, sans rien envoyer à l'extérieur. »

---

## Filet de sécurité (si quelque chose coince en direct)
- Le pipeline est **long** (CPU) : si la réunion presse, montrer la PR **#19 déjà traitée** sur GitHub (commentaires déjà visibles) + la ligne en base — c'est aussi convaincant et instantané.
- Si un conteneur semble bloqué : `docker compose ps` puis `docker compose restart <service>`.
- Garder des **captures d'écran** des sorties attendues (logs, commentaires GitHub, ligne Postgres) comme secours.
- Ne jamais improviser une commande : tout est ici, prêt à copier-coller.
