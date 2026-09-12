# Proofbound paper

Build the paper from this directory:

```sh
./build.sh
```

Requirements: Pandoc and XeLaTeX. The script writes the review copy to
`../../output/pdf/proofbound.pdf` and leaves a local copy beside the source.

The figures are native TikZ vectors embedded in `proofbound.md`. They are
intentionally part of the source so the paper, diagrams, and claims evolve
together.
