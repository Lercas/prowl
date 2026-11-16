#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE:?}" "${DIGEST:?}" "${RELEASE_TAG:?}" "${SYFT_CMD:?}" "${RUNNER_TEMP:?}" "${GITHUB_REPOSITORY:?}"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$RELEASE_TAG"
root="$RUNNER_TEMP/prowl-image"
mkdir "$root"

cosign sign --yes "$IMAGE@$DIGEST"
# Verification payloads go to /dev/null: a printed SPDX attestation is a multi-megabyte
# single line that stalls the Actions log processor after the script has finished.
# set -e still fails the step on any verification error.
cosign verify --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE@$DIGEST" >/dev/null
docker buildx imagetools inspect "$IMAGE@$DIGEST" --raw > "$root/index.json"
python3 scripts/release/platforms.py "$root/index.json" > "$root/platforms.txt"
while read -r arch platform_digest; do
  sbom="$root/prowl-image-linux-$arch.spdx.json"
  "$SYFT_CMD" scan --quiet "registry:$IMAGE@$platform_digest" --output "spdx-json=$sbom"
  python3 -c 'import sys; sys.path.insert(0,"scripts/release"); from pathlib import Path; from verify_artifacts import verify_sbom; verify_sbom(Path(sys.argv[1]))' "$sbom"
  cosign attest --yes --predicate "$sbom" --type spdxjson "$IMAGE@$platform_digest"
  cosign verify-attestation --type spdxjson --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE@$platform_digest" >/dev/null
done < "$root/platforms.txt"

printf '%s\n' "$DIGEST" > "$root/prowl-image-digest.txt"
(
  cd "$root"
  sha256sum prowl-image-digest.txt prowl-image-linux-amd64.spdx.json prowl-image-linux-arm64.spdx.json > prowl-image-checksums.txt
  cosign sign-blob --yes --bundle prowl-image-checksums.txt.sigstore.json prowl-image-checksums.txt
  cosign verify-blob --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle prowl-image-checksums.txt.sigstore.json prowl-image-checksums.txt
)
gh release upload "$RELEASE_TAG" \
  "$root/prowl-image-digest.txt" "$root/prowl-image-linux-amd64.spdx.json" \
  "$root/prowl-image-linux-arm64.spdx.json" "$root/prowl-image-checksums.txt" \
  "$root/prowl-image-checksums.txt.sigstore.json"
