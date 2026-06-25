# GIFs animés — registre & instructions

Les GIFs sont placés dans `presentation/gifs/`. Le générateur les insère
automatiquement (helper `gif_box`) : **GIF présent → affiché** ; sinon **image
statique de repli + badge « ▶ GIF à venir »**. Aucune modification de code
nécessaire pour ajouter un GIF — il suffit de déposer le fichier au bon nom.

> En mode **Présentation** PowerPoint, un GIF **se lit et boucle automatiquement**
> (aucun clic). En vue Édition / dans le PDF d'aperçu, seule la 1ʳᵉ image s'affiche.

## État

| Fichier (`gifs/`) | Slide | Contenu à capturer | État |
|-------------------|-------|--------------------|------|
| `demo_pr18.gif`   | 15 — Démonstration | défilement de la revue PR #18 jusqu'au verdict **BLOCK** | ✅ **fait** (généré depuis `pr_review_full_result.png`) |
| `pipeline.gif`    | 12 — Pipeline | le graphe LangGraph s'exécutant nœud par nœud (ou logs du pipeline) | ⏳ placeholder |
| `scanners.gif`    | 14 — Défense en profondeur | les cinq scanners s'exécutant en parallèle (terminal) | ⏳ placeholder |
| `grafana_live.gif`| 17 — Observabilité | un dashboard Grafana qui se met à jour en direct | ⏳ placeholder |
| `chat_demo.gif`   | 18 — Chat opérationnel | le chat répondant à « Quel est l'usage CPU ? » avec appel d'outil | ⏳ placeholder |

## Comment ajouter un GIF (prochaine itération)

1. **Capturer** l'écran (ScreenToGif sous Windows, ou Kap/Gifox sous macOS), ou
   **convertir une vidéo** : `ffmpeg -i clip.mp4 -vf "fps=12,scale=1000:-1" out.gif`.
2. Garder court (**5–12 s**), **rogné** sur la zone lisible, **largeur ~1000 px**,
   **boucle infinie**. Éviter le plein écran (texte illisible en 256 couleurs).
3. Déposer sous le **nom exact** du tableau ci-dessus dans `presentation/gifs/`.
4. Régénérer : `cd /opt/devsecops/presentation && python3 build_pptx_modern.py`.
   Le badge « ▶ GIF à venir » disparaît, le GIF prend la place du visuel statique.

## Reproduire / régler le GIF de démo

Généré par défilement vertical de `MASTER_PFE/img/chapter_4/pr_review_full_result.png`
(1920×7663) — viewport 1000×580, 72 images, ~11 fps, maintien 1,5 s sur le verdict
BLOCK, boucle infinie (~2,7 Mo). Pour le régénérer/ajuster, voir le bloc Pillow
utilisé (largeur, `vh`, nombre d'images, `duration`, `colors`).
