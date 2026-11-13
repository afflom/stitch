#!/usr/bin/env bash
# Actions-host orchestration only. The committed SDK owns all formal operations.
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in docker node; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required authoring executable missing: $tool" >&2; exit 69; }
done
[ -z "${PRISM_CODE_DRY_RUN:-}" ] || { echo 'dry-run axiom output cannot qualify authoring' >&2; exit 2; }
# A fresh checkout cannot reuse an old generated output by directory ordering.
[ ! -e app/.lexlean ] && [ ! -e app/.prism ] || { echo 'authoring needs a fresh checkout without compiler output' >&2; exit 2; }
mkdir -p verification-output
sha256sum prismpm.lock standards.lock package-lock.json scripts/check-model-sdk.sh > verification-output/unchanged-inputs.sha256
SDK_IMAGE=$(node -e 'const x=JSON.parse(require("fs").readFileSync("prismpm.lock"));if(!/^ghcr\.io\/uor-foundation\/[a-z0-9-]+@sha256:[0-9a-f]{64}$/.test(x.sdk_image))throw Error("unpinned SDK");console.log(x.sdk_image)')
node -e 'if(JSON.parse(require("fs").readFileSync("node_modules/prism-code/package.json")).version!=="0.7.2")throw Error("authoring requires pinned prism-code 0.7.2")'
run_sdk() {
  docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,exec,nosuid,size=3g \
    --volume "$PWD:$PWD" --workdir "$PWD" \
    --env HOME=/tmp/prismpm-home --env PRISMPM_EPHEMERAL_HOME=1 \
    "$SDK_IMAGE" "$@"
}
docker pull "$SDK_IMAGE"
run_sdk sh -c 'lexlean --version; lean --version; prismpm --version' > verification-output/compiler-identity.log
node scripts/check-facets.mjs --write
run_sdk sh scripts/check-model-sdk.sh --prepare
run_sdk sh -c 'cd app && lexlean fmt --check && lexlean lock --check'
# Fail before expensive proof if the actual formatter and source renderer differ.
node scripts/check-facets.mjs --check
# The supported Prism check validates official facet projections, not just Lean types.
run_sdk prismpm --project app check 2>&1 | tee verification-output/prismpm-check.log
# The unmodified verifier enforces every declared exact axiom policy itself.
# A policy mismatch (including LLV7005) fails here; no helper result can override it.
if run_sdk sh -c 'cd app && lexlean verify --all' > verification-output/lexlean-verify.stdout.log 2> verification-output/lexlean-verify.stderr.log; then
  cat verification-output/lexlean-verify.stdout.log
  node scripts/retain-authoring-evidence.mjs verification-output/lexlean-verify.stdout.log
else
  status=$?
  cat verification-output/lexlean-verify.stdout.log
  cat verification-output/lexlean-verify.stderr.log >&2
  exit "$status"
fi
# Only host projections and byte inventories are written after source verification.
node scripts/check-model.mjs --write
node scripts/check-facets.mjs --check
node scripts/check-product.mjs --write
node scripts/check-source-evidence.mjs
sha256sum -c verification-output/unchanged-inputs.sha256
printf '%s\n' 'Source authoring and proof retention only. Run the unchanged native Prism gate separately; PP5007 has not been cleared.'
