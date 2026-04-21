#!/usr/bin/env bash

program_name="soc-cli"

date=$(date '+%Y%m%d')
short_sha=$(git rev-parse --short HEAD)

version=""
platform=""

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -v, --version VERSION    Version string (default: from version.txt)"
    echo "  -p, --platform PLATFORM  Build only for this platform (e.g. linux/amd64)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Available platforms: windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/amd64"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            version="$2"
            shift 2
            ;;
        -p|--platform)
            platform="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

# Determine the version: CLI flag > version.txt > dev-<short_sha>
if [ -z "$version" ]; then
    if [ -f version.txt ]; then
        version=$(tr -d '\r' < version.txt | awk '{gsub(/^[ \t]+|[ \t]+$/, ""); print}')
    fi

    if [ -z "$version" ]; then
        echo "No version specified, defaulting to dev-${short_sha}"
        version="dev-${short_sha}"
    else
        echo "Using version from version.txt: ${version}"
    fi
fi

mkdir -p build

ldflags="-X 'soc-cli/cmd.Version=${version}' -X 'soc-cli/cmd.Commit=${short_sha}' -X 'soc-cli/cmd.Date=${date}'"

all_targets=(
    "windows amd64 .exe"
    "windows arm64 .exe"
    "darwin amd64 "
    "darwin arm64 "
    "linux amd64 "
)

# Filter to a single target if --platform was given
if [ -n "$platform" ]; then
    IFS='/' read -r filter_os filter_arch <<< "$platform"
    if [ -z "$filter_os" ] || [ -z "$filter_arch" ]; then
        echo "Invalid platform format: '${platform}'. Expected os/arch (e.g. linux/amd64)"
        exit 1
    fi

    targets=()
    for t in "${all_targets[@]}"; do
        # shellcheck disable=SC2206
        parts=($t)
        if [[ "${parts[0]}" == "$filter_os" && "${parts[1]}" == "$filter_arch" ]]; then
            targets+=("$t")
        fi
    done

    if [ ${#targets[@]} -eq 0 ]; then
        echo "Unknown platform: '${platform}'"
echo "Available platforms: windows/amd64, darwin/amd64, darwin/arm64, linux/amd64, windows/arm64"
        exit 1
    fi

    echo ":: Removing existing build for ${filter_os}/${filter_arch}..."
    rm -f "build/${program_name}_"*"_${filter_os}_${filter_arch}"*
else
    targets=("${all_targets[@]}")
    echo ":: Removing existing ${program_name}_* files..."
    rm -f build/${program_name}_*
fi

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
