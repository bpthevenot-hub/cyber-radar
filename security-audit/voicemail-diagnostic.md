# 📞 Diagnostic — messagerie vocale qui ne remonte plus (iPhone)

Problème type : des correspondants laissent des messages vocaux, mais tu ne les reçois plus /
ne les vois plus. Ce guide isole la cause **sans conclure hâtivement au piratage**.

> Une messagerie vocale qui bugue **n'est PAS**, à elle seule, une preuve de SIM swap.
> Le SIM swap se prouve autrement (§4 ci-dessous).

## 1. Test contrôlé (à documenter — date, heure, résultat)

1. Depuis **une autre ligne**, appelle ton numéro. **Ne réponds pas.**
2. Laisse un message : dis l'heure exacte + une phrase de test (« test répondeur 14h32 »).
3. Attends ~5 minutes.
4. Vérifie, dans l'ordre :
   - notification « Messagerie vocale » ;
   - onglet **Messagerie** de l'app Téléphone ;
   - appel **direct au répondeur** (appui long sur `1` ou numéro opérateur) ;
   - SMS éventuel de l'opérateur avec le message.
5. **Interprétation clé :**
   - Message présent en appelant le répondeur, **mais** absent de l'onglet Messagerie
     → problème **iOS / messagerie visuelle** (§2, cas A/C).
   - Message **absent partout**, y compris au répondeur direct
     → problème de **renvoi côté opérateur** (§2, cas B) ou boîte pleine.
   - Aucune notification mais message visible → problème **notifications** (§2, cas D).

Répète si possible depuis un **second opérateur** (mobile d'un proche) pour écarter un souci
propre à un réseau.

## 2. Causes classées par probabilité, et correctif (réversible)

| Cas | Cause | Vérifier / Corriger |
|---|---|---|
| **A** | Messagerie visuelle **désynchronisée** (fréquent) | Réglages → redémarrer l'iPhone. Puis Réglages → Téléphone. Souvent suffit. |
| **B** | **Renvoi conditionnel** vers le répondeur cassé (fréquent après portage/eSIM) | Vérifie le renvoi « sur non-réponse / occupé / injoignable » vers le numéro de messagerie de l'opérateur. Si absent → les messages n'arrivent jamais. Reconfigurer via l'app/opérateur. |
| **C** | **Live Voicemail** en conflit avec le répondeur opérateur | Réglages → Téléphone → **Messagerie vocale en direct** : teste en la désactivant puis réactivant. |
| **D** | **Notifications** coupées | Réglages → Notifications → Téléphone (badge + sons) ; vérifie Focus/Concentration & « Ne pas déranger ». |
| **E** | **Boîte vocale pleine** | Écoute/supprime d'anciens messages via le répondeur opérateur. |
| **F** | **Numéro de messagerie** incorrect | Compose le code opérateur de réinitialisation du numéro de messagerie. |
| **G** | Mauvaise **ligne par défaut** (double SIM/eSIM) | Réglages → Téléphone → Numéro par défaut ; vérifie quelle ligne porte le répondeur. |
| **H** | **Silence des appelants inconnus** / numéros bloqués | Réglages → Téléphone → « Silence des appelants inconnus » ; liste des numéros bloqués. |
| **I** | **Provisioning opérateur incomplet** (après portage récent) | Réglages → Général → Informations : accepte une éventuelle **mise à jour des réglages opérateur** ; réinsère l'eSIM si besoin. |

> **Niveau C (validation requise)** : réinitialisation des réglages réseau, réinitialisation
> de l'eSIM/SIM — ne les fais qu'après avoir épuisé A–I, car elles peuvent couper la ligne.

## 3. Distinguer les scénarios

- **Panne technique** (A–I) : réseau et appels normaux, seule la voix-messagerie déraille.
- **Incident opérateur** : plusieurs services affectés, souvent temporaire → vérifier le
  statut réseau de l'opérateur.
- **Sécurité** (§4) : accompagné d'autres signaux forts.

## 4. Volet sécurité — signes qui, EUX, évoquent un détournement

Ne conclure à une attaque **que** si ≥1 signal fort ci-dessous est présent :

- [ ] Perte **soudaine et totale** de réseau alors que la couverture est normale (signe SIM swap).
- [ ] Notification « votre numéro a été **porté** » ou « eSIM activée » non sollicitée.
- [ ] SMS/e-mail de l'opérateur confirmant un **changement de compte / de code messagerie** non initié.
- [ ] **Renvoi d'appel** vers un numéro **inconnu** configuré à ton insu (Réglages → Téléphone →
      Renvoi d'appel).
- [ ] Appareil **Apple inconnu** dans ton compte : appstoreconnect… non — via
      **Réglages → [ton nom] → Appareils**, ou iCloud.com → Appareils.
- [ ] Numéro de **confiance** modifié dans l'Apple ID / Google / Microsoft.
- [ ] Codes de vérification reçus **sans** que tu te connectes.

**Si un renvoi d'appel vers un numéro inconnu est présent → c'est CONFIRMÉ (détournement).**
Actions : le supprimer, appeler l'opérateur pour verrouiller la ligne (PIN de portabilité /
RIO), puis sécuriser Apple ID / Google / Microsoft (mot de passe + MFA depuis un appareil sain).

## 5. Fiche à remplir (pour le rapport §25)

```
Cause identifiée :
Preuve (résultat du test §1) :
Correction appliquée :
Test effectué (date/heure) :
Résultat après correction :
Action opérateur nécessaire : OUI / NON — laquelle :
Statut : RÉPARÉE / PARTIELLE / NON RÉPARÉE
```
