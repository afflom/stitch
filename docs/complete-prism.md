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
it must fail while the expanded source lacks matching genuine proof output.
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
3. The actual npm-lock-pinned `prism-code@0.7.2 axioms --write --project app`
   writer on the Actions host. That official writer delegates to the committed
   SDK through host Docker; it is not run inside a nested Docker container.
4. Canonical formatting, source-lock and facet freshness checks, followed by a
   real `lexlean verify --all` in the committed SDK.
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
