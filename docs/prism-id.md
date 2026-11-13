# Prism id

Prism id is a login-free identity. A prism comes into being in the browser the
first time it is used, and its id is the kappa of its genesis record. No
account, password, email, OAuth provider or server is involved.

- Model: `app/src/Stitch/PrismId.lex.tex` (`Stitch.PrismId`). Every
  authorization decision in the runtime calls its generated binding.
- Runtime: `src/prism-id.js`.
- Tests: `tests/prism-id.test.js`.

## Kappa

kappa = `sha256:` + lowercase hex SHA-256 of uor-addr canonical JSON: RFC 8785
shape, strings must already be NFC (they are refused, not normalized), integers
only, object members ordered by the UTF-8 bytes of their names. This matches
LexLean's `kappa` package and PrismPM ADR-017. It differs from the older
`docs/canonical-json.md` form, which sorts by UTF-16 and does not check NFC.

## Records

| Kind | Signed by | Meaning |
| --- | --- | --- |
| `prism/device/1` | none (public record) | A device's class (`browser`, `native`, `mobile`, `embedded`, `recovery`), its claimed key protection (`software`, `platform`, `secure-element`, `threshold-shares`), its P-256 signing and agreement public keys, and an optional ML-KEM-768 public key (`kem`). Its kappa is the device id. Private keys are non-extractable. |
| `prism/genesis/1` | the first device | Creates the prism. prism id = kappa of this body. The first device is a member. |
| `prism/bind/1` | an active member | Links a device as a `member` (no scope), a `delegate` (a non-empty list of actions), or the `recovery` device. Once a recovery device exists, only it may bind a new one. |
| `prism/revoke/1` | a linked member | Removes a device. `keep` lists the binds the revoked device made that stay valid. `epoch` and `wraps` carry a new private boundary key wrapped to each remaining member. |
| `prism/action/1` | an active device | An action for a host: `action`, `audience`, `payload`, `at`, `nonce`. A recovery device never signs one. |
| `prism/persona/1` | an active member | Names the persona prism for one host, and carries its recovery key wrapped to the main recovery device. Main log only. |
| `prism/persona-key/1` | an active device | Asks for this device's persona key for one host to be bound in that persona. Main log only. |

The prism log is a set of signed records keyed by the kappa of each envelope, so
merging two logs is set union: commutative, associative and idempotent.
`resolvePrism` decides which devices are active, using
`Stitch.PrismId.bindAllowed` and `deviceMaySign`.

Revocation wins over a concurrent bind: a bind made by a revoked device counts
only if the revocation lists it in `keep`. Rotating away from the genesis device
keeps every device that was already linked. Two members that revoke each other
are both revoked. The recovery device's revocations take precedence: a device it
revoked has no revocations that count (`Stitch.PrismId.revocationCounts`), and a
member can neither revoke it nor replace it (`recoveryBindAllowed`).

## Device classes and roles

Every device, whether a browser tab, a native install, a mobile app or an embedded device, uses the same records and the same primitives: P-256 ECDSA and ECDH, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM and SHA-256. P-256 is the curve that WebCrypto, Apple Secure Enclave, Android Keystore, TPM 2.0 and common secure elements all support, so a native implementation can keep its keys in hardware.

A **member** holds the private boundary and can link and revoke devices. A **delegate** is scoped: it may sign only the actions in its scope, never receives the private boundary, and cannot link or revoke (`Stitch.PrismId.mayAdminister`, `receivesPrivateBoundary`, `actionAllowed`). Embedded devices join as delegates.

The `protection` field is the device's own claim. A host that requires hardware-held keys admits a device only through `admitDevice(policy, record, evidence, verifiers)`: a verifier the host pinned for the evidence format must confirm hardware protection of exactly this device's signing key (`Stitch.PrismId.attestationBinds`, `hostAdmitsDevice`). Platform verifiers (App Attest, Android key attestation, TPM) plug in as host code.

A **hardened** device (`hardenSession`) keeps only non-extractable seal and topic keys derived from each boundary key, never the raw bytes. Script in its origin can use them while it runs but cannot copy them out. A hardened device can sync, seal, link delegates and revoke; it cannot link members or set up recovery (`Stitch.PrismId.mayShareBoundary`). Hardening every browser and keeping one native or mobile member as the sharing device is the recommended layout.

A native implementation checks itself against `tests/fixtures/prism-id-vectors.json`. `scripts/verify-prism-id-vectors.py` is an independent implementation of the canonical form that does exactly that.

## Linking a device out of band

1. An active device creates a link offer: prism id, a one-time 32-byte secret,
   an ephemeral ECDH public key, and an expiry. `uri` is what a QR code carries.
2. The new device scans it, and posts a link request to the rendezvous topic
   derived from the secret. The request carries its device record and an HMAC
   under the secret.
3. Both devices show a six-digit code derived from the secret and the joining
   device's kappa. The person confirms that the codes match. Someone who
   photographed the QR code and answered first gets a different code.
4. The offering device accepts only if `Stitch.PrismId.linkOfferAccepted`
   holds (code confirmed, secret matches, not yet used, not expired). It signs
   a bind. For a member, it wraps the boundary keyring to the new device's
   keys: ephemeral ECDH, plus ML-KEM-768 when the device advertises it, into
   HKDF (salt = secret) and AES-GCM. A delegate gets no wrap.
5. The new device checks that the prism lists it with the offered role,
   unwraps the keyring if it is a member, and holds the full log.

The offer URI is plain text, so any channel works: a QR code, NFC, a USB or
serial provisioning line, or typed text.

## Revocation rotates the private boundary

Every revocation carries a new boundary key, wrapped to each remaining member
with a fresh ephemeral ECDH key. The current key is the one with the highest
epoch, and ties go to the smaller kappa. A device without the current key
refuses to seal (`Stitch.PrismId.boundaryKeyAdmitted`). The sync topic is
derived from the current key, so a revoked device loses the topic too. After a
rotation, publish once under the previous key so that devices still listening
there take up the new key. Content sealed under earlier keys stays readable to
the devices that hold them.

## Post-quantum wraps

Every key wrap (linking, rotation, recovery shares, persona recovery) is
hybrid when the recipient's device record carries `kem`: both the ECDH and the
ML-KEM-768 shared secrets feed HKDF, so the wrap holds if either does. A wrap to
such a device without the KEM part is refused, and so is a sender that cannot
encapsulate (`Stitch.PrismId.hybridWrapRequired`). Devices advertise `kem` when
their WebCrypto has ML-KEM (Node 24 does). Signatures stay P-256 ECDSA.

## Recovery

`createRecovery(session, { threshold, guardians })` binds a recovery device
whose private keys, together with a snapshot of the boundary keyring, exist only
as Shamir shares over GF(256). Each share is wrapped to one guardian: a device
of another prism the person trusts, a spare device of their own, or
`{ paper: true }` for a share to print. Every later rotation also wraps the new
boundary key to the recovery device.

After losing every device, the person creates a new device. Each guardian
confirms the person out of band, compares `recoveryCode(prism, record)` on both
screens, and calls `releaseShare`, which re-wraps the share to the new device.
`recoverPrism` refuses below the threshold (`Stitch.PrismId.thresholdMet`),
binds the new device as a member, revokes every other device ever linked
(including a thief's, whose revocations then stop counting), carries personas
over, and with `rotateRecovery` replaces the recovery device with fresh shares
so the recovered secret is retired. The prism log it takes is a copy obtained
from the substrate, where the recovery keyring can open it, or from any holder.

## Personas: one id per host

A host never sees the main prism. `ensurePersona(session, audience)` creates a
persona for that host: a prism of its own, with a non-extractable persona key on
each device. Two hosts see unrelated prism ids and keys, so they cannot link the
person. The persona-to-host map lives only in the main log, which travels sealed
between members. Members keep personas in step on sync: they bind persona keys
requested by active devices with the same role and scope, and revoke persona
keys of devices the main prism revoked. A persona's recovery key is wrapped to
the main recovery device, so recovery restores every persona whose log the host
supplies. `personaFor` returns what a host needs, and `signPersonaAction` signs
under the persona.

## Actions at a host

A device signs an action for one `audience` (a host), with a nonce and a time.
The host verifies it against the prism log: it must be fresh, unseen and for
this audience (`Stitch.PrismId.actionFresh`), and it must come from an active
device inside its scope (`Stitch.PrismId.actionAllowed`). This is how foundry
grants a stakeholder the permissions of their prism context. Hosts are given
the persona for their audience, not the main prism.

## Boundaries

A prism has a private boundary (a key held only by its linked devices) and then
everyone else. A boundary with two or more identities is shared, and is public
to its members (`Stitch.PrismId.boundaryShared`). A published boundary is public
to all. `sealPrivate` and `openPrivate` keep content in the private boundary;
the sealed object's kappa is its address.

## Sync over the substrate

Linked devices sync on a topic derived from the private boundary key, so only
they can find it. Each message is the log and the persona logs, sealed in the
private boundary, bound to the prism id, and padded (ISO 7816-4) to a
power-of-two bucket of at least 1 KiB so relays learn only the bucket. Messages over 4 MiB and logs over 4096 records are refused
before any parsing or signature work. The bus contract is `publish(topic, bytes)` and
`subscribe(topic, fn)`. `createMemoryBus` implements it for tests; the stitch
substrate implements it across peers and federation nodes.

The threat and security model is in `docs/prism-id-threat-model.md`.
