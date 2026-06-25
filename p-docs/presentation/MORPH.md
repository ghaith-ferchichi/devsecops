# Animations — guide PowerPoint (BTE Security AI Agent)

Le deck `BTE_Security_AI_Agent_Soutenance.pptx` embarque déjà des animations.
Ce guide explique (1) ce qui est **automatique**, (2) comment ajouter le **Morph**
cinématique sur 2–3 moments, (3) options & rappels.

> Aperçu : LibreOffice rend le PDF **sans jouer** les animations. Ouvre le `.pptx`
> dans **PowerPoint** (ou Mode Présentation) pour les voir.

---

## 1. Déjà automatique (rien à faire)

- **Transition *Fade* sur les 26 slides** — enchaînement fluide et pro.
- **Entrées *Fade-in* au clic** sur 4 slides clés (révélation élément par élément) :
  - **Slide 3** — les 3 cartes de stats (24 h→15 min · 5/5 · 0) apparaissent une par une.
  - **Slide 13** — les 6 cartes du manifeste agentique, une par une.
  - **Slide 14** — les 7 étapes du pipeline, une par une (l'auditoire « voit le cerveau s'assembler »).
  - **Slide 18** — le badge **`VERDICT : BLOCK`** apparaît en dernier (effet de chute).

  → En présentation : **clic** (ou flèche droite) pour révéler l'élément suivant.

---

## 2. Ajouter le Morph (cinématique, ~5 min)

Le Morph fait *glisser/redimensionner* les objets entre deux slides quasi identiques.
Il n'est pas auto-générable ; voici les 2 effets qui valent le coup.

### A. Zoom fluide dans un diagramme (recommandé — slide 9, 11 ou 13)
Pour entrer en douceur dans l'architecture / le graphe LangGraph :
1. Sélectionne la slide (ex. **11 — pipeline**). **Clic droit → Dupliquer la slide**.
2. Sur la **copie** (slide 11b), sélectionne l'image du diagramme et **agrandis-la**
   (coins) pour zoomer sur la zone voulue ; recadre le texte si besoin.
3. Sélectionne la slide 11b → onglet **Transitions → Morph** (durée ~0,75 s).
4. En présentation : slide 11 (vue d'ensemble) → clic → **zoom fluide** sur la slide 11b.

### B. Titre → ouverture (optionnel)
1. **Transitions → Morph** (ou *Push* doux) sur la **slide 2** : l'accroche entre en glissé
   depuis le titre.

> Astuce Morph : il anime les objets qui **portent le même nom/identité** entre les 2
> slides. Le plus simple est de **dupliquer** puis **modifier** (déplacer/agrandir), comme ci-dessus.

---

## 3. Ajouter d'autres entrées (optionnel, fiable)

Pour animer un autre objet (ex. les puces d'une slide) :
1. Sélectionne l'objet → onglet **Animations → Fade (Apparition en fondu)**.
2. **Démarrer : Au clic** (ou *Après la précédente* pour un build auto).
3. **Volet Animation** pour réordonner. Garde **Fade** partout (évite Spin/Bounce/Fly — daté).

---

## 4. Police (look exact)

Les titres utilisent **Segoe UI Semibold** (présent sous Windows → rendu fidèle).
Pour un rendu encore plus « designer », installe la police gratuite **Poppins**
(Google Fonts) et remplace la police des titres par *Poppins SemiBold* (Accueil →
Remplacer les polices). Sinon, ne rien faire : Segoe UI Semibold est très propre.

---

## 5. Avant la soutenance

- **Répète à 14:00** (marge sur 15 min). Chronométre chaque partie.
- **Démo enregistrée** prête en secours (slide 18) — ne jamais dépendre du VPS en direct.
- Sur les slides à build (3, 13, 14, 18), **un clic = un élément** : entraîne-toi au rythme.
- Mode Présentateur : garde tes notes à l'écran, l'auditoire voit les slides.

---

## 6. Régénérer le deck

Toute modif de contenu/design passe par le générateur (les animations sont
réinjectées automatiquement) :
```bash
cd /opt/devsecops/presentation && python3 build_pptx_modern.py
```
Les retouches **manuelles** (Morph, polices) faites dans PowerPoint sont **perdues**
si on régénère — applique-les en dernier, sur une copie figée.
