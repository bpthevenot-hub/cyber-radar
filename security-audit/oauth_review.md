# Revue & révocation des applications OAuth

Une application OAuth malveillante est l'un des vecteurs de persistance les plus courants :
elle survit au changement de mot de passe et à la déconnexion des sessions. À traiter en priorité.

## Google

1. Ouvre **https://myaccount.google.com/connections** (« Applications et services tiers »).
2. Pour chaque application, regarde le **niveau d'accès** :
   - 🔴 **Critique** : « Lire, rédiger, envoyer et supprimer définitivement vos e-mails »,
     « accès complet au compte », « Gmail », « Drive : tous les fichiers ».
   - 🟠 Élevé : accès Contacts, Agenda, « voir vos e-mails ».
   - 🟢 Faible : « nom, adresse e-mail, photo de profil » (connexion simple).
3. **Signaux d'alerte** : application que tu ne reconnais pas ; nom générique
   (« Mail Client », « Sync », « Google »); accès Gmail complet pour un service qui n'en a
   pas besoin ; date de dernier accès récente alors que tu ne l'utilises pas.
4. **Révocation** : clique l'application → « Supprimer l'accès ». *Réversible* : il faudra
   ré-autoriser une app légitime au prochain usage. **Niveau B** (sûr) si l'app est clairement
   inconnue et à privilèges élevés.
5. Vérifie aussi les **extensions Chrome** ayant accès à `mail.google.com`
   (`chrome://extensions`) — une extension peut lire la boîte sans apparaître dans OAuth.

## Microsoft

1. Ouvre **https://myaccount.microsoft.com/** → « Confidentialité » / « Applications et services
   auxquels vous avez donné accès », et **https://account.live.com/consent/Manage** pour un
   compte personnel.
2. Pour un compte pro/école (TBS) : **https://myapps.microsoft.com/** liste tes apps ; la
   révocation de consentement d'entreprise peut dépendre de l'admin.
3. Révoque tout consentement inconnu demandant `Mail.ReadWrite`, `Mail.Send`,
   `MailboxSettings.ReadWrite`, `offline_access`, `full_access_as_user`.

## Après révocation (vérification — §23)

- Recharge la page : l'app doit avoir disparu.
- Relance `gmail_audit.py` / `graph_audit.py` : plus de constat OAuth élevé.
- Surveille les nouvelles connexions pendant quelques jours.

## Ordre de remédiation en cas de compromission confirmée (§22)

1. Préserver les preuves (export, captures, hash).
2. Sécuriser l'e-mail **et** le téléphone de récupération d'abord.
3. Révoquer les **sessions** inconnues (Google: `myaccount.google.com/device-activity`).
4. Révoquer les **applications OAuth** malveillantes (ce document).
5. Supprimer transferts / règles / filtres malveillants.
6. Regénérer MFA compromise + **nouveaux codes de secours**.
7. Changer le mot de passe **depuis un appareil sain**.
8. Contrôler les comptes liés et services sensibles (GitHub, Stripe, banques…).

> Ne change pas tous les mots de passe au hasard **avant** d'avoir sécurisé l'adresse et le
> numéro de récupération : sinon l'attaquant peut reprendre le compte via « mot de passe oublié ».
