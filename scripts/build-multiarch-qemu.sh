#!/usr/bin/env bash
# Build multi-architecture images using QEMU emulation
# This is simpler but slower than cross-compilation
#
# Environment variables:
#   PLATFORMS    - Target platforms (default: linux/amd64,linux/arm64)
#   IMAGE_NAME   - Image name (default: sks5)
#   IMAGE_TAG    - Image tag (default: latest)
#   PUSH         - Push to registry if set to "true"

set -euo pipefail

PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
IMAGE_NAME="${IMAGE_NAME:-sks5}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PUSH="${PUSH:-false}"
BUILDER_NAME="sks5-multiarch"

# --- Detect container engine ---
detect_engine() {
    if command -v docker &>/dev/null && docker buildx version &>/dev/null; then
        echo "docker"
    elif command -v podman &>/dev/null; then
        echo "podman"
    else
        echo "ERROR: Neither 'docker buildx' nor 'podman' found." >&2
        exit 1
    fi
}

ENGINE=$(detect_engine)
echo "Using container engine: $ENGINE"
echo "Platforms: $PLATFORMS"
echo "Image: $IMAGE_NAME:$IMAGE_TAG"

# --- Docker buildx path ---
build_with_docker() {
    # Check QEMU binfmt support
    if [ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
        echo "WARNING: QEMU binfmt not detected for aarch64."
        echo "Install it with one of:"
        echo "  docker run --privileged --rm tonistiigi/binfmt --install all"
        echo "  sudo apt-get install qemu-user-static binfmt-support"
        echo "  sudo dnf install qemu-user-static"
        echo ""
        echo "Attempting to continue anyway (buildx may handle it)..."
    fi

    # Create or reuse builder
    if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
        echo "Creating buildx builder: $BUILDER_NAME"
        docker buildx create --name "$BUILDER_NAME" --driver docker-container --use
    else
        echo "Reusing buildx builder: $BUILDER_NAME"
        docker buildx use "$BUILDER_NAME"
    fi

    local push_flag=""
    local output_flag=""
    if [ "$PUSH" = "true" ]; then
        push_flag="--push"
    else
        # --load does not support multi-platform; use OCI output for local
        output_flag="--output type=oci,dest=${IMAGE_NAME}-${IMAGE_TAG}-multiarch.tar"
        echo "NOTE: Local multi-arch build will be saved as OCI tarball"
        echo "      Use PUSH=true to push to a registry instead"
    fi

    docker buildx build \
        --platform "$PLATFORMS" \
        -f Containerfile \
        -t "${IMAGE_NAME}:${IMAGE_TAG}" \
        $push_flag $output_flag \
        .
}

# --- Podman path ---
build_with_podman() {
    # Check QEMU binfmt support
    if [ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
        echo "WARNING: QEMU binfmt not detected for aarch64."
        echo "Install it with one of:"
        echo "  sudo apt-get install qemu-user-static binfmt-support"
        echo "  sudo dnf install qemu-user-static"
        echo ""
        echo "Attempting to continue anyway..."
    fi

    local manifest="${IMAGE_NAME}:${IMAGE_TAG}"

    # Remove existing manifest if present
    podman manifest rm "$manifest" 2>/dev/null || true
    podman manifest create "$manifest"

    # Build for each platform
    IFS=',' read -ra ARCH_LIST <<< "$PLATFORMS"
    for platform in "${ARCH_LIST[@]}"; do
        echo ""
        echo "=== Building for $platform ==="
        podman build \
            --platform "$platform" \
            -f Containerfile \
            --manifest "$manifest" \
            .
    done

    if [ "$PUSH" = "true" ]; then
        echo ""
        echo "=== Pushing manifest ==="
        podman manifest push "$manifest" "docker://${manifest}"
    else
        echo ""
        echo "Manifest created locally: $manifest"
        echo "Use PUSH=true to push to a registry"
    fi
}

# --- Main ---
case "$ENGINE" in
    docker) build_with_docker ;;
    podman) build_with_podman ;;
esac

echo ""
echo "Multi-arch build (QEMU) complete."
