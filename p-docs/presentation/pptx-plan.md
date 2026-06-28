# Plan de la présentation — Soutenance PFE (VERSION VERROUILLÉE · 15 min)
**Projet :** BTE Security AI Agent — Agent IA agentique pour la revue automatisée de code
**Auteur :** Ghaith Ferchichi · ISI / Université Tunis El Manar · BTE
**Durée :** **15 min (cible 14:00 + marge)** · Q&A séparé
**Langue :** Français · **Outil :** PowerPoint (.pptx) · **Thème :** Academic (clair, plein jour)
**Format :** **~26 slides** (20 contenu + 6 dividers « Plan »), granulaire, une idée/slide.

> **Fil rouge unique :** « Nous n'avons pas automatisé un pipeline —
> **nous avons construit un cerveau.** » Tout sert ce récit et met en valeur
> **(1) l'IA agentique** et **(2) la cybersécurité**. Trois pics : agentique · démo ·
> auto-conscience.

---

## 1. Principes directeurs

- **Une idée par slide, piloté par les figures** — le jury retient les schémas.
- **15 min = discipline.** ~30–35 s/slide ; la démo ≈ 2 min ; dividers ≈ 5 s.
  Au-delà de ~26 slides → on court → on paraît mal préparé. Tout slide « nice to
  have » est coupé (→ §7 slides de secours).
- **Dividers « Plan » (timeline 6 nœuds)** avant chaque partie, nœud courant
  surligné — repère de navigation (convention ISI).
- **Annoncer la contribution tôt** (slide 3) et la re-citer 3× (claim, pic P3, clôture).
- **Tout chiffrer :** 24 h → 15 min · 7/7 détectées · −50 % durée · −52 % tokens ·
  5 scanners · 0 code dehors · 19 outils · 28 métriques · 11 conteneurs.
- **Une value line ferme chaque partie** (transforme la fonctionnalité en valeur, §3b).
- **Cohérence visuelle :** thème Academic, dividers, couleurs verdict (vert/ambre/rouge),
  numéros de slide.

---

## 2. Budget temps (hard 15:00)

| Temps | Partie | Pic |
|-------|--------|-----|
| 0:00–1:30 | Ouverture : accroche → **la contribution** | tension |
| 1:30–3:30 | P1 Contexte : écart AS-IS (24 h, selon le relecteur) | |
| 3:30–5:00 | P2 Fondements : pourquoi local (moat) + les briques | |
| 5:00–8:00 | **P3 Le cerveau** : manifeste + pipeline + confiance | ★ agentique |
| 8:00–11:00 | **P4 Sécurité** : défense en profondeur + **DÉMO** | ★ démo |
| 11:00–13:30 | **P5 Visibilité** : voit tout + **bug Phi-4 auto-détecté** | ★ le cerveau |
| 13:30–15:00 | P6 Bilan : limites + GPU + thèse + merci | atterrissage |

---

## 3. Squelette slide par slide (~26 slides)

> `[Plan▸N]` = divider timeline (helper `plan_divider()`, §12). Figures → §9.

**Ouverture**
1. **Titre** — projet, *titre officiel « Agent IA pour revue automatisée de code »*,
   auteur, encadrants (M. Kamel KAOUECH — Expert Infrastructure ; Mme Ghayet El Mouna
   ZHIOUA — Maître Assistant(e)), logos couleur BTE/ISI/UTM, 2025–2026.
2. **Accroche** — stat choc (argument *shift-left* : une vulnérabilité coûte bien plus
   chère en production qu'en revue — *source à vérifier*) + *« Une seule injection SQL
   fusionnée dans une API de paiement peut compromettre la banque. »*
3. **La contribution + 3 stats** — *« Un agent IA autonome qui revoit chaque PR selon
   l'OWASP Top 10 en 15 min, publie les correctifs, et s'exécute 100 % en local —
   aucun code ne quitte la banque. »* Stats : **24 h→15 min · 7/7 · 0 code dehors**.

**P1 · Contexte général**
4. `[Plan▸1]` Contexte général.
5. **BTE & processus AS-IS** — Fig 1.2 (`asis_workflow`) : revue manuelle, limites en rouge.
6. **Problématique** — délai **jusqu'à 24 h selon la disponibilité et l'expertise du
   relecteur** · aucun gate CI/CD · secrets & dépendances manqués.
7. **Solution proposée — TO-BE** — Fig 1.4 (`tobe_workflow`) : l'agent en un schéma.
   *Value line : « une revue lente et dépendante du relecteur — un angle mort bancaire. »*

**P2 · Fondements & choix**
8. `[Plan▸2]` Fondements & choix.
9. **Pourquoi 100 % local + positionnement** — Tableau 2.8 : vs CodeQL/Snyk/SonarQube/
   Copilot ; *« rien ne sort du VPS »* = conformité BCT (le moat). Petit encart NF
   (confidentialité, perf 15–25 min, résilience, observabilité).
10. **Les briques** — hub radial : 5 scanners SAST + 2 LLM locaux (7B/14B) + LangGraph.

**P3 · Le cerveau : architecture ★**
11. `[Plan▸3]` Le cerveau de l'agent.
12. **Vue d'ensemble** — Fig 3.1 (`full_architecture`) : 11 conteneurs, 4 couches.
13. **Pourquoi c'est un AGENT, pas un appel LLM** — 6 capacités (§4). Le manifeste.
14. **Le pipeline de revue** — Fig 3.3 (`langgraph_state_graph`), animé : webhook →
    classify → route → scan → analyze → verdict → publish.
15. **Confiance** — Fig 3.9 (`anti_hallucination_layers`, 6 couches) + Fig 3.2
    (`two_model_architecture`, 7B/14B, −50 %). Répond au doute n°1 du jury sur les LLM.
    *Value line : « un agent qui raisonne, agit et reprend après panne. »*

**P4 · La sécurité en action ★**
16. `[Plan▸4]` La sécurité en action.
17. **Défense en profondeur** — Fig 2.2 (`sast_tools_overview`) : 5 scanners + LLM,
    complémentarité (le LLM rattrape un secret manqué par Gitleaks).
18. **DÉMO PR #19** (≈2 min) — vidéo/captures : revue auto → 7 suggestions inline →
    verdict **`BLOCK`** → check commit rouge.
19. **Bénéfices & preuve** — Tableau 4.14 (AS-IS/TO-BE) + Tableau 4.13 (**7/7 détectées**).
    *Value line : « la sécurité passe d'un contrôle humain variable à un gate systématique
    et conforme. »*

**P5 · Visibilité totale & autonomie ★**
20. `[Plan▸5]` Le cerveau voit tout & s'auto-exploite.
21. **Le cerveau voit tout le VPS** — Fig 3.12 (`monitoring_stack`) + 3 dashboards Grafana
    (`grafana_*`) : 28 métriques, 15 alertes.
22. **Chat 19 outils + autonomie** — Fig 3.10 (`inter_react`) : interroger l'infra en
    langage naturel ; scheduler, health digest Slack, gardien disque auto-réparateur.
23. **Il voit ses propres pannes** — la télémétrie A/B a capté un bug Phi-4 silencieux
    (0 token, aucun log) → **0 → 51 tokens** après correctif. *Le « c'est un cerveau ».*
    *Value line : « un système qui voit tout le VPS et repère ses propres pannes. »*

**P6 · Bilan & perspectives**
24. `[Plan▸6]` Bilan & perspectives.
25. **Limites + Perspectives** — CPU ~3 tok/s, durcissement, corpus restreint →
    migration GPU (2–5 min/PR, ~3000 €), passage à l'échelle des dépôts BTE.
26. **Conclusion + Merci** — re-citer la thèse *« un cerveau remis à la BTE »* + ligne
    personnelle + remerciements jury.

---

## 3b. Fil rouge, pics & value lines

**Fil rouge :** *« un cerveau, pas un pipeline »* — il **perçoit** (webhooks),
**raisonne** (LLM + graphe d'état), **agit** (revue, gate, Slack), **voit tout le VPS**
(observabilité + chat) et **s'auto-exploite** (scheduler, gardien disque).

**3 pics à mettre en scène :** (1) le **manifeste agentique** (slide 13) ; (2) la
**démo** BLOCK (slide 18) ; (3) **il détecte ses propres pannes** (slide 23).

**Value line en clôture de chaque partie** (P1→P6, cf. §3) — la phrase qui transforme
la fonctionnalité en valeur métier.

---

## 4. Mettre en valeur l'IA AGENTIQUE (slide 13 + progression P3→P5)

**Slide 13 — 6 capacités (le manifeste) :**
- **Perception** → webhooks GitHub.
- **Raisonnement** → classe la PR, route le graphe, choisit les scanners.
- **Action** → commente, fixe le gate (APPROVE/REQUEST_CHANGES/BLOCK), escalade Slack.
- **État & reprise** → checkpoints LangGraph (PostgreSQL) ; survit au redémarrage.
- **Usage d'outils** → 19 outils réels (Docker, Prometheus, Redis…).
- **Auto-exploitation** → scheduler, health digest, gardien disque.

**Progression qui élève « outil » → « système » :** architecture (12) → confiance (15)
→ autonomie & sens (21–23). La phrase qui tue le doute « wrapper ChatGPT ? » : les 6
capacités sont **réellement construites**.

---

## 5. Mettre en valeur la CYBERSÉCURITÉ (5 angles, fil tout au long)

1. **Défense en profondeur** — 5 scanners spécialisés **+** consolidation LLM,
   complémentaires (histoire du secret manqué par Gitleaks, capté par le LLM).
2. **Shift-left + gate** — le verdict est un *contrôle technique* : PR vulnérable **bloquée**.
3. **Confidentialité = sécurité** — inférence 100 % locale = conformité BCT (argument
   le plus fort pour une banque, devant la qualité de détection).
4. **Gouvernance & auditabilité** — chaque revue persistée → tableau de risque RSSI.
5. **L'agent se sécurise lui-même** — webhooks HMAC, secrets exclus des prompts, plan
   de durcissement assumé (penser en défenseur sur sa propre surface d'attaque).

---

## 6. Les 4 money moments + la démo

1. **Le claim** (slide 3) — dit lentement, 3 stats à l'écran.
2. **La démo** (slide 18) — PR vulnérable → BLOCK + fixes, en direct (enregistrée).
3. **L'auto-conscience** (slide 23) — *« sa télémétrie a détecté un bug qui ne produisait
   aucun log »* — la preuve que c'est un cerveau, pas un script.
4. **Le moat** (slide 9) — *« zéro ligne de code ne quitte la banque »*.

**Démo :** l'enregistrer (fallback vidéo prêt), narration par-dessus, ~2 min. Jamais de
live sans backup.

---

## 7. Slides de secours Q&A (masquées, après la 26) + contenu coupé

Pré-construire pour répondre instantanément **et** loger ce qu'on a coupé du flux 15 min :
- Méthodologie Scrumban + Gantt (10 sprints, pull-system).
- Besoins fonctionnels / non-fonctionnels (détaillés).
- Évaluation 2nd backend LocalAI vs Ollama (+22 %).
- Diff parser anti-hallucination (machine à états) · mémoire PostgreSQL (E-A).
- Tests de validation (HMAC, dédup, circuit breaker, gardien disque).
- Questions types : pourquoi local ? · confiance LLM ? · vrais bugs vs plantés ? ·
  perf CPU/échelle (GPU) ? · faux positifs ? · vs SonarQube/Copilot ? · coût ?

> **Risque assumé :** Besoins F/NF est replié dans la slide 9. Si le jury est strict
> sur la spécification, ajouter 1 slide Besoins et couper la slide 10 (hub).

---

## 8. Décisions verrouillées

- **Durée 15 min · ~26 slides · Français · PowerPoint.**
- **Thème : « Modern Light Tech »** (blanc + violet IA + teal + or, sans bold,
  images/icônes, animations fluides — voir §11). *Remplace le thème Academic.*
- **Dividers timeline : 6 nœuds** (Contexte · Fondements · Cerveau · Sécurité ·
  Visibilité · Bilan).
- **Métaphore cerveau = fil rouge léger** (pas d'anatomie lourde sur chaque slide).
- **Animations : hybride** — Fade + builds injectés automatiquement, Morph manuel sur
  2–3 slides pics (script fourni).
- **Démo enregistrée + fallback · Présentateur solo (Ghaith).**
- **Chiffre clé revue manuelle = 24 h** (selon la disponibilité et l'expertise du relecteur).

---

## 9. Inventaire des figures (depuis `MASTER_PFE/img/**`)

| Slide | Figure / visuel | Fichier |
|-------|-----------------|---------|
| 5  | Processus AS-IS | `asis_workflow` |
| 7  | Solution / TO-BE | `tobe_workflow` (ou `solution_overview`) |
| 9  | Positionnement (Tableau 2.8) | table recréée |
| 10 | Hub des briques | recréé (hub radial) + `sast_tools_overview` |
| 12 | Architecture globale | `full_architecture` |
| 13 | 6 capacités | icônes (sans figure) |
| 14 | Graphe LangGraph | `langgraph_state_graph` |
| 15 | Anti-hallucination + 2 modèles | `anti_hallucination_layers` · `two_model_architecture` |
| 17 | 5 outils SAST | `sast_tools_overview` |
| 18 | Démo PR #19 | `pr_comment-*` · `github_inline_suggestions` · vidéo |
| 19 | AS-IS/TO-BE + 7/7 | tables recréées (4.14 / 4.13) |
| 21 | Observabilité + dashboards | `monitoring_stack` · `grafana_vps_host_dashboard` · `grafana_agent_dashboard` · `grafana_pr_reviews_dashboard` |
| 22 | Chat + autonomie | `inter_react` · `chat_ui_screenshot` · `scheduler_tasks` · `slack_health_digest` |
| 23 | Bug Phi-4 auto-détecté | callout métrique (0→51) · `grafana_agent_dashboard` (rows A/B) |

Logos couleur : `logo_BTE.png` · `LogoISI.png` · `Logo_UTM.png`.

---

## 10. Prochaine étape

- [x] Plan 15 min verrouillé.
- [ ] Ajouter `plan_divider(s, active_index, titre)` au générateur (timeline 6 nœuds).
- [ ] Construire les ~26 slides sur le thème **Academic** + rendre l'aperçu.
- [ ] Slides Q&A de secours + notes orateur minutées.
- [ ] Embarquer la vidéo de démo PR #19 (slide 18).

---

## 11. Système de design — « Modern Light Tech » (clair, plein jour)

Direction retenue : base **blanche**, **sans bold**, riche en **images + icônes**,
motifs décoratifs légers, **animations fluides** (voir § Animations ci-dessous).
Inspirée des deux templates — composants du *Cyber-AI Thesis* (dividers, jauges,
nœuds) + langage clair du *White & Purple* (blobs, grilles de points, cartes
arrondies) — adaptée à notre identité. **Nos diagrammes/dashboards/démo sont les
images héros ; aucune photo « stock » générique.**

**Palette (sur blanc)**

| Rôle | Hex | Usage |
|------|-----|-------|
| Canvas | `#FFFFFF` | fond |
| Panneau / carte | `#F2F4F7` | callouts, cartes gris clair |
| Encre / titres | `#0B2545` | titres + texte fort |
| Texte courant | `#33405C` | paragraphes |
| **Signature IA — violet** | `#7C5CFC` (fill) / `#6D28D9` (texte) | l'accent **agentique** |
| Tech / sécurité — teal | `#2BA6AE` (fill) / `#157A82` (texte/traits) | second accent |
| Identité BTE — or | `#E0A100` (fills uniquement) | rappel BTE |
| Neutres / filet | `#5B6B7B` / `#E1E7ED` | secondaire, séparateurs |

**Règle d'or :** violet/teal/or vifs = **remplissages d'icônes/formes uniquement**,
jamais du texte sur blanc ; versions foncées (`#6D28D9`, `#157A82`) pour texte/traits.

**Sémantique verdicts :** APPROVE `#1E9E5A` · REQUEST_CHANGES `#E08600` · BLOCK `#D7263D`.

**Signature IA :** dégradé **violet → teal** (`#7C5CFC → #2BA6AE`), réservé aux formes
des moments agentiques (divider P3, manifeste, hero cerveau).

**Typographie :** titres **Poppins / Montserrat SemiBold** (sans géométrique, grand et
gras comme les templates) · corps **Segoe UI** · mono **Consolas**. Fallback Windows :
**Segoe UI Semibold** si Poppins absent.

**Motifs décoratifs** (légers, jamais sur le contenu) : blobs organiques violet/teal/or
en coin · grilles de points · arcs concentriques en coin · chevrons `›››` · petit carré
/ barres verticales comme marque de titre · cartes images à coins arrondis + ombre
douce · callouts gris arrondis.

**Bibliothèque de composants** (helpers générateur, §12) :
- `title_split()` — texte gauche + image héro à droite + chevron
- `section_divider()` — grand numéro + titre + accent image clair + filet
- `plan_divider(active)` — frise 6 pastilles circulaires (active = violet plein)
- `stat_donuts()` — 3 jauges circulaires % (24 h→15 min · 7/7 · 0)
- `icon_triad()` — 3 grandes icônes + label + texte (manifeste)
- `icon_list_panel()` — panneau gris + badges circulaires (besoins/bénéfices)
- `image_cards()` — grille de cartes images arrondies (dashboards, démo)
- `hero_image()` — image cadrée centrale + chevrons
- `callout()` — bulle grise arrondie + icône flèche
- `verdict_badge()` — pastille APPROVE / REQUEST_CHANGES / BLOCK

**Système d'animation — le « wow », fluide :**
- **Transitions :** **Fade** sur toutes les slides (injecté automatiquement — fluide, sûr).
- **Builds (entrées) :** **Fade-in par étapes** sur les slides clés (injecté) — pipeline
  (14, nœud par nœud), manifeste (13, 6 cartes), stats (3, jauges), démo (18, badge
  `BLOCK` en Zoom/punch).
- **Morph (cinématique) :** 2–3 moments pics (dividers timeline, zoom diagramme, hero
  cerveau) — **à appliquer dans PowerPoint** (script fourni), non auto-générable par
  python-pptx.
- **À éviter :** spin, bounce, fly-from-edge (daté).

---

## 12. Génération du .pptx (référence build)

- **Nouveau générateur à écrire :** `presentation/build_pptx_modern.py` (thème Modern
  Light Tech, §11). Réécriture autour de la **bibliothèque de composants** (§11). Les
  anciens `build_pptx.py` / `build_pptx_academic.py` servent de base (helpers `txt()`,
  `fit_image()`, `set_gradient()`, tables) mais palette/typo/composants changent.
- **Helpers à implémenter :** `title_split`, `section_divider`, `plan_divider(active)`,
  `stat_donuts`, `icon_triad`, `icon_list_panel`, `image_cards`, `hero_image`,
  `callout`, `verdict_badge` + injection **Fade transitions** et **builds fade-in** (XML).
- **Sortie :** `BTE_Security_AI_Agent_Soutenance.pptx`.
- **Régénérer :** `cd /opt/devsecops/presentation && python3 build_pptx_modern.py`
- **Prévisualiser :** `soffice --headless --convert-to pdf --outdir /tmp/pptx_preview <pptx>`
  puis lire le PDF (note : l'aperçu LibreOffice ne joue pas les animations). python-pptx
  + libreoffice-impress déjà installés.
- **Livrable additionnel :** `MORPH.md` — script pas-à-pas pour appliquer Morph sur les
  2–3 slides pics dans PowerPoint.
