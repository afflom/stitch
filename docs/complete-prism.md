# Complete Stitch product model

Stitch's product model is a source-owned description of the product, not a
claim that every host service or deployment is formally verified. The canonical
contracts remain in `app/src/`. The facet generator derives the product catalog
and its public presentation from those contracts and explicit project resources.

## Sources, projections and evidence

- `Product.Model` names components, capabilities, assumptions, dependencies,
  deployment contracts and shipped assets. Asset records name files and their
  origin; they do not embed their changing byte hashes.
- `Product.Architecture` describes the component graph and its stakeholder views.
  Additional Product facets describe features, journeys, design, security,
  quality, brand, users, persistence, release and compliance. The exact module
  names, declarations, input paths and assurance limits are generated in
  [`product/facets.json`](../product/facets.json).
- `scripts/check-facets.mjs` produces the formal facet sources and source-derived
  catalog. Its `--check` mode refuses drift instead of silently repairing it.
  [`site/facets.json`](../site/facets.json) is a display projection of the same
  catalog. Its labels are source-inventory descriptions, not verification badges.
- `scripts/check-model.mjs` generates the existing small JavaScript projection
  from its supported formal source subset. It is not a compiler or proof checker.
- `scripts/check-product.mjs` verifies asset coverage and binds exact local bytes
  in [`product/contracts.json`](../product/contracts.json). The inventory includes
  source/vocabulary inputs, retained evidence, provenance and licenses,
  documentation, test/checking code and workflows. It refuses missing files,
  symlinks, stale facet inputs and browser files absent from the source register.
- `scripts/check-source-evidence.mjs` independently checks the retained source
  attestation, build manifest, complete current input closure and pinned tool
  identities. A new or changed formal module makes historic evidence stale.
  Regenerating a catalog cannot repair that failure.

The catalogs do not issue certificates. A source proof does not establish native
Prism artifact acceptance, measured usability, a complete security assessment,
whole-browser correctness, network availability or deployment readiness.
Unmeasured quality and external-service assumptions remain explicit open work.

## Verified source checkpoint

[Source authoring run 43451144439](https://github.com/afflom/stitch/actions/runs/43451144439)
started from `6c393bf736e316a9f58db38a3cc498948bd226fe` and used the unchanged
SDK and standards pins. Its real authoring command generated the source lock
for the official `prism.arch`, `prism.qual` and `prism.sec` closure, formatted
zero modules and passed the actual `prismpm --project app check`.

Unmodified LexLean/Lean/leanchecker verification accepted all 38 modules and
1,910 declaration audits, with 124 successful processes (83 Lean and 41
leanchecker). The exact reported attestation is
`f29ee1259ab249c9ee90c9820aeb1a29988317cb82a9cf3759d57d468d52469a`.
The [source summary](../product/source-verification.json),
[original attestation](../product/source-attestation.json) and
[original build manifest](../product/source-build-manifest.json) retain that
result. The strict retention check binds them to 100 current source inputs
and the immutable SDK's proof-tool identities.

The [original authoring artifact](https://github.com/afflom/stitch/actions/runs/43451144439/artifacts/14052920216)
is 4,072,450 bytes with SHA-256
`168d84c92d72bd787efde97ca1b0594c903d48d23b08d95581c9cf0efb5c1b1a`.
The imported source lock and proof records came from those original bytes;
no generated formal source, axiom policy, SDK pin or proof gate was changed.
With its generated lock and retained evidence, the authoring run passed all
419 JavaScript tests and all five strata. Independently,
[the exact-input Chromium job](https://github.com/afflom/stitch/actions/runs/43451144395/job/131973315941)
passed 14 browser scenarios on `6c393bf`.

These are source and scoped runtime/browser results. Native Prism artifact
acceptance remains pending; the separate old-SDK `PP5007` issue is not cleared
by this checkpoint. Physical network/NAT trials, other browsers and whole-host
refinement remain outside this evidence.

## Local generation and checks

With the lock-pinned Node dependencies installed:

```sh
npm ci --ignore-scripts
npm run facets:write
npm run model:write
npm run product:write
npm run product:check
npm run evidence:check
npm test
python3 scripts/verify-custody.py
npm run test:browser
```

`product:write` refreshes source-derived facets first and then records the final
resource bytes. It neither invokes the formal toolchain nor changes retained
verification records. A normal `npm test` includes strict source-evidence tests;
it must fail whenever current source lacks matching genuine proof output.
Do not remove, skip or relax those tests to make an authoring branch appear green.

The facet renderer must match the pinned compiler's canonical formatting and
observed axiom policies. If the real formatter changes generated source, retain
that original authoring output and fix the renderer before calling freshness
checks successful. Do not rewrite source after proving a different version.

## Artifact-only hosted authoring

[Source authoring workflow](../.github/workflows/source-authoring.yml) runs only
on `afflom/stitch` branch `feat/complete-stitch-prism`. It has read-only repository
permissions, does not retain checkout credentials, and never pushes, merges,
deploys, publishes a release, or changes the SDK pin.

[`scripts/author-source.sh`](../scripts/author-source.sh) orchestrates:

1. A fresh checkout, the exact image from `prismpm.lock`, and unchanged SDK,
   standards, npm and native-gate inputs.
2. Facet generation followed by the unchanged SDK `--prepare` authoring command.
3. Canonical formatting, source-lock and facet freshness checks, then the actual
   `prismpm --project app check` for official facet projection acceptance. A
   failed Prism check stops before proof retention.
4. Unmodified `lexlean verify --all` in the committed SDK. It enforces every
   exact declared axiom policy, runs the real Lean/leanchecker proof stages and
   emits its own original attestation. An axiom-policy refusal such as LLV7005
   remains a failure; no convenience-helper result can override it.
5. Selection of exactly the attestation ID printed by that successful process.
   `scripts/retain-authoring-evidence.mjs` reads that specific verified directory
   and the build ID it binds, checks original manifest bytes, then delegates to
   the existing strict retention helper. It never chooses the first, newest or
   last generated output directory, and never constructs proof records.
6. Regeneration of host bindings and the byte register, strict source freshness
   validation and the normal Node suite.

On success or failure, the workflow uploads original logs, authoring files,
compiler output and a full Git patch for review. A failed process cannot reach
retention, even if its stdout contains success-like text. Review and verify the
artifact against its exact workflow source before importing generated changes.
A workflow artifact alone is not authority to accept arbitrary supplied JSON.


## Explicit axiom authoring and the pinned helper defect

When a declaration actually requires an authoring-policy change, the official
writer remains a separate, explicit host command using the existing pinned
package and SDK:

```sh
node node_modules/prism-code/bin/prism-code.mjs axioms --write --project app
```

It is not an automatic proof prerequisite. On
[authoring run 43445915817](https://github.com/afflom/stitch/actions/runs/43445915817)
for source `5002a66d01915161049506198b05bbd1ec443b56`, the SDK passed source checking
for all 38 modules. The pinned `prism-code@0.7.2` helper then missed 15 real Lean
axiom reports because it parses one line at a time and Lean wrapped the bracketed
axiom lists across lines. It incorrectly reported an existing Budget declaration
as unaudited. The original audit process exited successfully and contains the
missing report; the package and its parser have not been patched locally.

The exact original Budget audit bytes are retained in
[`budget-audit.process.json`](evidence/source-authoring/5002a66d/budget-audit.process.json),
with [artifact provenance](evidence/source-authoring/5002a66d/provenance.json).
The complete original artifact is
[14047868120](https://github.com/afflom/stitch/actions/runs/43445915817/artifacts/14047868120),
3,924,126 bytes, SHA-256
`c30544930868cd51ba3dc81b058257777db9478aba303846ce9d47d4399c92e7`.
Diagnostic reading of those original wrapped reports found no policy mismatches
or unaudited declarations among the 1,378 source definitions/theorems. That
observation is not proof or authorization to rewrite policies. The helper stopped
before certificate publication; only a successful strict verifier run on the
current source can establish its source proof.

Default authoring therefore runs the strict owning verifier directly. No proof
stage, exact-axiom check, policy or verification flag is removed. If a real policy
mismatch is reported, stop and retain that diagnostic; use a correctly functioning
official authoring path rather than silently editing installed dependencies or
inventing observations. The native Prism gate remains independent and unchanged.

## Native acceptance remains a separate gate

The committed `prismpm.lock` and `standards.lock` remain unchanged. The unchanged
`scripts/check-model-sdk.sh --check` still owns native Prism/Holo verification.
The known old-SDK `PP5007: application-lean timed out` is not cleared by source
proof, catalog freshness, runtime tests, the site demonstration or an authoring
artifact. See [native build diagnosis](native-build-diagnosis.md).

Only adopt a replacement SDK after its owner qualifies the complete immutable
image and matching standards. Review the supported lock-update proposal, retain
new proof from the adopted toolchain, and pass the unchanged native gate on the
same final source. Runtime, browser, guest provenance and licensing checks remain
independent requirements for the final branch and deployment.
