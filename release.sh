#!/usr/bin/env bash
set -e

if [ -z "${1:-}" ]; then
    echo "Usage: $0 vX.Y.Z"
    exit 1
fi

tag="$1"

echo ":: Version: ${tag} (tag: ${tag})"

if git rev-parse "$tag" >/dev/null 2>&1; then
    echo "Tag ${tag} already exists"
    exit 1
fi

echo ":: Building..."
make release VERSION="$tag"

echo ":: Signing checksums..."
read -rs -p "GPG passphrase: " gpg_pass
echo ""
echo "$gpg_pass" | gpg --yes --batch --armor --detach-sign \
    --pinentry-mode loopback --passphrase-fd 0 \
    --local-user B48204F5147B5BB26D4DAF219E7BEA3EC8E8258B dist/SHA256SUMS

echo ""
echo "Summary:"
echo "  Tag:       ${tag}"
echo "  Artifacts:"
for f in dist/*.tar.gz dist/*.zip dist/SHA256SUMS dist/SHA256SUMS.asc; do
    echo "    $f"
done
echo ""
read -r -p "Push tag and publish release? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo ":: Tagging ${tag}..."
git tag -a "$tag" -m "$tag"
git push origin "$tag"

echo ":: Creating GitHub release..."
gh release create "$tag" \
    dist/*.tar.gz \
    dist/*.zip \
    dist/SHA256SUMS \
    dist/SHA256SUMS.asc \
    --title "$tag" \
    --generate-notes

echo "Released ${tag}!"
