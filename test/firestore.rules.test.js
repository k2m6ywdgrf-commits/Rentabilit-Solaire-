// Tests des règles Firestore (test/firestore.rules.test.js).
//
// Ces tests tournent contre l'émulateur Firestore et vérifient la logique
// d'autorisation de firestore.rules telle qu'elle est réellement écrite dans
// le dépôt — placeholder d'UID admin inclus. Comme isAdmin() ne fait que
// comparer request.auth.uid à cette chaîne, les tests restent valides quelle
// que soit la vraie valeur collée en production : seul le *comportement* des
// règles est vérifié, jamais un secret.
//
// Lancer : npm run test:rules  (démarre l'émulateur, exécute les tests, l'arrête)

import { before, beforeEach, after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  initializeTestEnvironment,
  assertSucceeds,
  assertFails
} from '@firebase/rules-unit-testing';
import {
  doc, getDoc, setDoc, updateDoc, deleteDoc,
  collection, getDocs
} from 'firebase/firestore';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Doit correspondre exactement à la chaîne présente dans firestore.rules.
const ADMIN_UID = 'REPLACE_WITH_ADMIN_UID';
const ALICE_UID = 'alice-uid';
const BOB_UID = 'bob-uid';
const ALICE_EMAIL = 'alice@example.com';

let testEnv;

before(async () => {
  testEnv = await initializeTestEnvironment({
    projectId: 'suivi-solaire-rules-test',
    firestore: {
      rules: fs.readFileSync(path.join(__dirname, '..', 'firestore.rules'), 'utf8'),
      host: '127.0.0.1',
      port: 8080
    }
  });
});

after(async () => {
  await testEnv.cleanup();
});

beforeEach(async () => {
  await testEnv.clearFirestore();
});

// Prépare un état (bypass des règles) pour tester la lecture/écriture ensuite.
async function seed(fn) {
  await testEnv.withSecurityRulesDisabled(async (ctx) => fn(ctx.firestore()));
}

describe('/admin/{doc} — sonde de détection admin', () => {
  it("refuse la lecture à un utilisateur non authentifié", async () => {
    const db = testEnv.unauthenticatedContext().firestore();
    await assertFails(getDoc(doc(db, 'admin', 'status')));
  });

  it("refuse la lecture à un utilisateur authentifié non-admin", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(getDoc(doc(db, 'admin', 'status')));
  });

  it("autorise la lecture et l'écriture pour l'UID admin", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(getDoc(doc(db, 'admin', 'status')));
    await assertSucceeds(setDoc(doc(db, 'admin', 'status'), { ok: true }));
  });
});

describe('/approvals/{uid} — création de la demande', () => {
  it("autorise un utilisateur à créer sa propre demande pending avec les bons champs", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertSucceeds(setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
  });

  it("refuse la création d'une demande pour un autre uid", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'approvals', BOB_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
  });

  it("refuse la création avec un statut différent de pending (auto-approbation)", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'approved', requestedAt: new Date()
    }));
  });

  it("refuse la création avec un e-mail différent de celui du compte connecté", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'approvals', ALICE_UID), {
      email: 'usurpe@example.com', displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
  });

  it("refuse la création avec un champ supplémentaire non attendu", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date(), role: 'admin'
    }));
  });
});

describe('/approvals/{uid} — lecture', () => {
  beforeEach(async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
  });

  it("autorise un utilisateur à lire sa propre demande", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertSucceeds(getDoc(doc(db, 'approvals', ALICE_UID)));
  });

  it("refuse à un utilisateur la lecture de la demande d'un autre", async () => {
    const db = testEnv.authenticatedContext(BOB_UID, { email: 'bob@example.com' }).firestore();
    await assertFails(getDoc(doc(db, 'approvals', ALICE_UID)));
  });

  it("refuse à un non-admin de lister l'ensemble des demandes", async () => {
    const db = testEnv.authenticatedContext(BOB_UID, { email: 'bob@example.com' }).firestore();
    await assertFails(getDocs(collection(db, 'approvals')));
  });

  it("autorise l'admin à lire une demande individuelle et à lister la collection", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(getDoc(doc(db, 'approvals', ALICE_UID)));
    await assertSucceeds(getDocs(collection(db, 'approvals')));
  });
});

describe('/approvals/{uid} — validation / refus', () => {
  beforeEach(async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
  });

  it("refuse à l'utilisateur lui-même de changer son propre statut (auto-validation)", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(updateDoc(doc(db, 'approvals', ALICE_UID), { status: 'approved' }));
  });

  it("refuse à l'utilisateur lui-même de supprimer sa demande", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(deleteDoc(doc(db, 'approvals', ALICE_UID)));
  });

  it("autorise l'admin à valider une demande", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(updateDoc(doc(db, 'approvals', ALICE_UID), { status: 'approved', decidedAt: new Date() }));
  });

  it("autorise l'admin à refuser une demande", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(updateDoc(doc(db, 'approvals', ALICE_UID), { status: 'rejected', decidedAt: new Date() }));
  });

  it("autorise l'admin à supprimer une demande", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(deleteDoc(doc(db, 'approvals', ALICE_UID)));
  });
});

describe('/users/{userId} — accès aux données selon le statut de validation', () => {
  it("refuse l'accès si aucune demande n'existe encore (compte tout juste connecté)", async () => {
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'users', ALICE_UID), { payloadJSON: '{}' }));
    await assertFails(getDoc(doc(db, 'users', ALICE_UID)));
  });

  it("refuse l'accès tant que la demande est en attente (pending)", async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'users', ALICE_UID), { payloadJSON: '{}' }));
  });

  it("refuse l'accès si la demande a été refusée", async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'rejected', requestedAt: new Date()
    }));
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(db, 'users', ALICE_UID), { payloadJSON: '{}' }));
  });

  it("autorise l'accès une fois la demande approuvée", async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'approved', requestedAt: new Date()
    }));
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertSucceeds(setDoc(doc(db, 'users', ALICE_UID), { payloadJSON: '{}' }));
    await assertSucceeds(getDoc(doc(db, 'users', ALICE_UID)));
  });

  it("autorise l'accès à une sous-collection une fois approuvé, la refuse sinon", async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: 'Alice', status: 'pending', requestedAt: new Date()
    }));
    const dbPending = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(setDoc(doc(dbPending, 'users', ALICE_UID, 'projets', '1'), { x: 1 }));

    await seed((db) => updateDoc(doc(db, 'approvals', ALICE_UID), { status: 'approved' }));
    const dbApproved = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertSucceeds(setDoc(doc(dbApproved, 'users', ALICE_UID, 'projets', '1'), { x: 1 }));
  });

  it("un utilisateur approuvé ne peut jamais lire/écrire les données d'un autre utilisateur", async () => {
    await seed(async (db) => {
      await setDoc(doc(db, 'approvals', ALICE_UID), { email: ALICE_EMAIL, displayName: '', status: 'approved', requestedAt: new Date() });
      await setDoc(doc(db, 'users', BOB_UID), { payloadJSON: '{"secret":true}' });
    });
    const db = testEnv.authenticatedContext(ALICE_UID, { email: ALICE_EMAIL }).firestore();
    await assertFails(getDoc(doc(db, 'users', BOB_UID)));
    await assertFails(setDoc(doc(db, 'users', BOB_UID), { payloadJSON: '{}' }));
  });

  it("l'admin garde toujours accès à son propre document, sans demande d'approbation", async () => {
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertSucceeds(setDoc(doc(db, 'users', ADMIN_UID), { payloadJSON: '{}' }));
    await assertSucceeds(getDoc(doc(db, 'users', ADMIN_UID)));
  });

  it("l'admin n'a PAS accès aux données privées d'un autre utilisateur (seulement à /approvals)", async () => {
    await seed((db) => setDoc(doc(db, 'users', BOB_UID), { payloadJSON: '{"secret":true}' }));
    const db = testEnv.authenticatedContext(ADMIN_UID).firestore();
    await assertFails(getDoc(doc(db, 'users', BOB_UID)));
  });

  it("refuse tout accès à un utilisateur non authentifié", async () => {
    await seed((db) => setDoc(doc(db, 'approvals', ALICE_UID), {
      email: ALICE_EMAIL, displayName: '', status: 'approved', requestedAt: new Date()
    }));
    const db = testEnv.unauthenticatedContext().firestore();
    await assertFails(getDoc(doc(db, 'users', ALICE_UID)));
  });
});
