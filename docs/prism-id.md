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
| `prism/device/1` | none (public record) | A device's P-256 signing and agreement public keys. Its kappa is the device id. Private keys are non-extractable. |
| `prism/genesis/1` | the first device | Creates the prism. prism id = kappa of this body. |
| `prism/bind/1` | an active device | Links another device to the prism. |
| `prism/revoke/1` | a linked device | Removes a device. `keep` lists the binds the revoked device made that stay valid. |

The prism log is a set of signed records keyed by the kappa of each envelope, so
merging two logs is set union: commutative, associative and idempotent.
`resolvePrism` decides which devices are active, using
`Stitch.PrismId.bindAllowed` and `deviceMaySign`.

Revocation wins over a concurrent bind: a bind made by a revoked device counts
only if the revocation lists it in `keep`. Rotating away from the genesis device
keeps every device that was already linked. Two devices that revoke each other
are both revoked; recovery (a later milestone) is the way out.

## Linking a device out of band

1. An active device creates a link offer: prism id, a one-time 32-byte secret,
   an ephemeral ECDH public key, and an expiry. `uri` is what a QR code carries.
2. The new device scans it, and posts a link request to the rendezvous topic
   derived from the secret. The request carries its device record and an HMAC
   under the secret.
3. The offering device accepts only if `Stitch.PrismId.linkOfferAccepted`
   holds (secret matches, not yet used, not expired). It signs a bind, and wraps
   the private boundary key with ECDH + HKDF (salt = secret) + AES-GCM.
4. The new device checks that the prism now lists it as active, unwraps the
   boundary key, and holds the full log.

## Boundaries

A prism has a private boundary (a key held only by its linked devices) and then
everyone else. A boundary with two or more identities is shared, and is public
to its members (`Stitch.PrismId.boundaryShared`). A published boundary is public
to all. `sealPrivate` and `openPrivate` keep content in the private boundary;
the sealed object's kappa is its address.

## Sync over the substrate

Linked devices sync on a topic derived from the private boundary key, so only
they can find it. Each message is the log sealed in the private boundary, bound
to the prism id. The bus contract is `publish(topic, bytes)` and
`subscribe(topic, fn)`. `createMemoryBus` implements it for tests; the stitch
substrate implements it across peers and federation nodes.
