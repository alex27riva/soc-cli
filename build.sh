#!/usr/bin/env bash

program_name="soc-cli"

date=$(date '+%Y%m%d')
short_sha=$(git rev-parse --short HEAD)

# Determine the version: CLI arg > version.txt > dev-<short_sha>
if [ -n "$1" ]; then
    version=$1
else
    # Try to read version from version.txt if it exists
    if [ -f version.txt ]; then
        # Read and trim whitespace
        version=$(tr -d '\r' < version.txt | awk '{gsub(/^[ \t]+|[ \t]+$/, ""); print}')
    fi

    if [ -z "${version}" ]; then
        echo "No version specified, defaulting to dev-${short_sha}"
        version="dev-${short_sha}"
    else
        echo "Using version from version.txt: ${version}"
    fi
fi

mkdir -p build

echo ":: Removing existing ${program_name}_* files..."
rm -f build/${program_name}_*

ldflags="-X 'soc-cli/cmd.Version=${version}' -X 'soc-cli/cmd.Commit=${short_sha}' -X 'soc-cli/cmd.Date=${date}'"

targets=(
    "windows amd64 .exe"
    "darwin amd64 "
    "darwin arm64 "
    "linux amd64 "
)

fail_count=0

for t in "${targets[@]}"; do
    # shellcheck disable=SC2206
    parts=($t)
    GOOS=${parts[0]}
    GOARCH=${parts[1]}
    ext=${parts[2]}

    out_name="${program_name}_${version}_${GOOS}_${GOARCH}${ext}"
    echo ":: Building for ${GOOS}/${GOARCH} -> ${out_name}"

    GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags "${ldflags}" -o "build/${out_name}"
    if [ $? -ne 0 ]; then
        echo "Failed to build for ${GOOS}/${GOARCH}."
        fail_count=$((fail_count+1))
    fi
done

if [ ${fail_count} -ne 0 ]; then
    echo "Build finished with ${fail_count} failure(s)."
    exit 1
fi

echo "Build completed successfully!"