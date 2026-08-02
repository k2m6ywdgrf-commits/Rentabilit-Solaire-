# Rentabilit-Solaire-

## Tests

Les règles Firestore (`firestore.rules`) sont couvertes par une suite de tests qui tourne
contre l'émulateur Firestore (aucun projet Firebase réel n'est contacté).

```bash
npm install
npm run test:rules
```

Nécessite Node.js et Java (utilisé par l'émulateur Firestore). Ces tests s'exécutent aussi
automatiquement sur chaque push/PR touchant `firestore.rules` (voir
`.github/workflows/firestore-rules-tests.yml`).
