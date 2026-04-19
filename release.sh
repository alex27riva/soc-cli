#!/usr/bin/env bash
set -e

if [ ! -f version.txt ]; then
    echo "version.txt not found"
    exit 1
fi

version=$(tr -d '\r' < version.txt | awk '{gsub(/^[ \t]+|[ \t]+$/, ""); print}')

if [ -z "$version" ]; then
    echo "version.txt is empty"
    exit 1
fi

tag="${version}"

echo ":: Version: ${version} (tag: ${tag})"

if git rev-parse "$tag" >/dev/null 2>&1; then
    echo "Tag ${tag} already exists"
    exit 1
fi

echo ":: Building..."
./build.sh -v "$version"

echo ":: Generating checksums..."
cd build
sha256sum soc-cli_* > checksums.txt

echo ":: Signing checksums..."
read -rs -p "GPG passphrase: " gpg_pass
echo ""
echo "$gpg_pass" | gpg --yes --batch --armor --detach-sign \
    --pinentry-mode loopback --passphrase-fd 0 \
    --local-user B48204F5147B5BB26D4DAF219E7BEA3EC8E8258B checksums.txt
cd ..

echo ""
echo "Summary:"
echo "  Tag:       ${tag}"
echo "  Artifacts:"
for f in build/soc-cli_* build/checksums.txt build/checksums.txt.asc; do
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
    build/soc-cli_* \
    build/checksums.txt \
    build/checksums.txt.asc \
    --title "$tag" \
    --generate-notes

echo "Released ${tag}!"
