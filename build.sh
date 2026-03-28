#!/bin/bash

set -e

# Build configuration
BINARIES=("darkscan" "darkscand" "darkscan-carve" "darkscan-stego")
BIN_DIR="./bin"
VERSION="1.0.0"  # TODO: Auto-detect from git tag or VERSION file
INSTALL_BASE="/usr/local/darkscan"
VERSION_DIR="${INSTALL_BASE}/${VERSION}"
PROD_LINK="${INSTALL_BASE}/prod"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Build single binary
build_binary() {
    local binary=$1
    local cmd_path="./cmd/${binary}"

    if [ ! -d "${cmd_path}" ]; then
        print_error "Command directory not found: ${cmd_path}"
        return 1
    fi

    print_info "Building ${binary}..."
    go build -o "${BIN_DIR}/${binary}" "${cmd_path}"

    if [ $? -eq 0 ]; then
        print_success "Built ${binary}"
        return 0
    else
        print_error "Failed to build ${binary}"
        return 1
    fi
}

# Build function (builds darkscan by default)
build() {
    print_info "Building darkscan..."

    # Create bin directory
    mkdir -p "${BIN_DIR}"

    # Download dependencies
    print_info "Downloading dependencies..."
    go mod download
    go mod tidy

    # Build the binary
    build_binary "darkscan"
}

# Build all binaries
build_all() {
    print_info "Building all binaries..."

    # Create bin directory
    mkdir -p "${BIN_DIR}"

    # Download dependencies
    print_info "Downloading dependencies..."
    go mod download
    go mod tidy

    # Build all binaries
    local failed=0
    for binary in "${BINARIES[@]}"; do
        if ! build_binary "${binary}"; then
            ((failed++))
        fi
    done

    echo ""
    if [ $failed -eq 0 ]; then
        print_success "All binaries built successfully!"
        print_info "Binaries in ${BIN_DIR}/:"
        ls -lh "${BIN_DIR}/" | tail -n +2 | awk '{print "  - " $9 " (" $5 ")"}'
    else
        print_error "${failed} binaries failed to build"
        return 1
    fi
}

# Install function
install() {
    # Build all binaries if they don't exist
    if [ ! -d "${BIN_DIR}" ] || [ -z "$(ls -A ${BIN_DIR} 2>/dev/null)" ]; then
        print_error "Binaries not found. Building all first..."
        build_all
    fi

    print_info "Installing DarkScan ${VERSION}..."

    # Check for sudo privileges
    if [ "$EUID" -ne 0 ]; then
        print_error "Installation requires sudo privileges"
        print_info "Rerunning with sudo..."
        sudo "$0" install
        exit $?
    fi

    # Create versioned directory structure
    print_info "Creating directory structure at ${VERSION_DIR}..."
    mkdir -p "${VERSION_DIR}/bin"
    mkdir -p "${VERSION_DIR}/sbin"
    mkdir -p "${VERSION_DIR}/libexec"
    mkdir -p "${VERSION_DIR}/etc"
    mkdir -p "${VERSION_DIR}/share/rules"
    mkdir -p "${VERSION_DIR}/share/signatures"
    mkdir -p "${VERSION_DIR}/var/quarantine"
    mkdir -p "${VERSION_DIR}/var/log"

    # Copy all binaries
    local installed=0
    for binary in "${BINARIES[@]}"; do
        if [ -f "${BIN_DIR}/${binary}" ]; then
            print_info "Installing ${binary}..."

            # Daemon goes in sbin, tools in bin
            if [[ "${binary}" == *"d" ]] && [[ "${binary}" != *"-"* ]]; then
                cp "${BIN_DIR}/${binary}" "${VERSION_DIR}/sbin/${binary}"
                chmod 755 "${VERSION_DIR}/sbin/${binary}"
            else
                cp "${BIN_DIR}/${binary}" "${VERSION_DIR}/bin/${binary}"
                chmod 755 "${VERSION_DIR}/bin/${binary}"
            fi
            ((installed++))
        else
            print_error "Binary not found: ${binary} (skipping)"
        fi
    done

    # Update or create 'prod' symlink
    print_info "Updating production version symlink..."
    if [ -L "${PROD_LINK}" ]; then
        local old_version=$(readlink "${PROD_LINK}" | xargs basename)
        print_info "Previous version: ${old_version}"
        rm "${PROD_LINK}"
    fi
    ln -sf "${VERSION}" "${PROD_LINK}"
    print_success "Production version set to: ${VERSION}"

    # Create system symlinks from prod version
    print_info "Creating system symlinks..."

    # Symlink binaries from prod/bin to /usr/local/bin
    for binary in "${BINARIES[@]}"; do
        local src_path=""
        if [[ "${binary}" == *"d" ]] && [[ "${binary}" != *"-"* ]]; then
            src_path="${PROD_LINK}/sbin/${binary}"
            if [ -f "${VERSION_DIR}/sbin/${binary}" ]; then
                ln -sf "${src_path}" "/usr/local/sbin/${binary}"
                print_success "  /usr/local/sbin/${binary} -> ${src_path}"
            fi
        else
            src_path="${PROD_LINK}/bin/${binary}"
            if [ -f "${VERSION_DIR}/bin/${binary}" ]; then
                ln -sf "${src_path}" "/usr/local/bin/${binary}"
                print_success "  /usr/local/bin/${binary} -> ${src_path}"
            fi
        fi
    done

    # Set proper ownership (root:wheel on macOS, root:root on Linux)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        chown -R root:wheel "${VERSION_DIR}"
    else
        chown -R root:root "${VERSION_DIR}"
    fi

    echo ""
    print_success "Installation complete!"
    print_info "Version directory: ${VERSION_DIR}"
    print_info "Production version: ${VERSION}"
    print_info "Installed ${installed} binaries"
    echo ""
    print_info "Available commands:"
    for binary in "${BINARIES[@]}"; do
        if [[ "${binary}" == *"d" ]] && [[ "${binary}" != *"-"* ]]; then
            if [ -f "${VERSION_DIR}/sbin/${binary}" ]; then
                print_info "  - ${binary} (daemon, in /usr/local/sbin)"
            fi
        else
            if [ -f "${VERSION_DIR}/bin/${binary}" ]; then
                print_info "  - ${binary}"
            fi
        fi
    done
    echo ""
    print_info "Version Management:"
    print_info "  Current:  ${PROD_LINK} -> ${VERSION}"
    print_info "  Rollback: sudo ln -sf /usr/local/darkscan/<old-version> ${PROD_LINK}"
    print_info "  Upgrade:  sudo ln -sf /usr/local/darkscan/<new-version> ${PROD_LINK}"
}

# Uninstall function
uninstall() {
    local version_to_remove="${1:-all}"

    print_info "Uninstalling DarkScan..."

    # Check for sudo privileges
    if [ "$EUID" -ne 0 ]; then
        print_error "Uninstallation requires sudo privileges"
        print_info "Rerunning with sudo..."
        sudo "$0" uninstall "${version_to_remove}"
        exit $?
    fi

    if [ "${version_to_remove}" == "all" ]; then
        # Remove all system symlinks
        print_info "Removing system symlinks..."
        for binary in "${BINARIES[@]}"; do
            if [[ "${binary}" == *"d" ]] && [[ "${binary}" != *"-"* ]]; then
                [ -L "/usr/local/sbin/${binary}" ] && rm -f "/usr/local/sbin/${binary}"
            else
                [ -L "/usr/local/bin/${binary}" ] && rm -f "/usr/local/bin/${binary}"
            fi
        done

        # Remove entire installation directory
        if [ -d "${INSTALL_BASE}" ]; then
            print_info "Removing ${INSTALL_BASE}..."
            rm -rf "${INSTALL_BASE}"
        fi

        print_success "Complete uninstallation finished!"
    else
        # Remove specific version
        local version_path="${INSTALL_BASE}/${version_to_remove}"

        if [ ! -d "${version_path}" ]; then
            print_error "Version ${version_to_remove} not found"
            return 1
        fi

        # Check if this is the production version
        if [ -L "${PROD_LINK}" ]; then
            local current_prod=$(readlink "${PROD_LINK}" | xargs basename)
            if [ "${current_prod}" == "${version_to_remove}" ]; then
                print_error "Cannot remove production version: ${version_to_remove}"
                print_info "Switch to another version first:"
                print_info "  sudo ln -sf /usr/local/darkscan/<other-version> ${PROD_LINK}"
                return 1
            fi
        fi

        print_info "Removing version ${version_to_remove}..."
        rm -rf "${version_path}"
        print_success "Version ${version_to_remove} removed"
    fi
}

# Clean function
clean() {
    print_info "Cleaning build artifacts..."
    rm -rf "${BIN_DIR}"
    go clean
    print_success "Clean complete"
}

# Show help
show_help() {
    cat << EOF
DarkScan Build Script

Usage: $0 [command] [options]

Commands:
    build       Build darkscan binary only (default)
    all         Build all binaries (darkscan, darkscand, darkscan-carve, darkscan-stego)
    install     Build and install all binaries with versioned deployment
    uninstall   Remove installation [version|all]
    clean       Remove build artifacts
    help        Show this help message

Installation Structure:
    ${INSTALL_BASE}/
    ├── ${VERSION}/          # Version-specific installation
    │   ├── bin/             # CLI tools
    │   ├── sbin/            # Daemons
    │   ├── etc/             # Configuration
    │   └── var/             # Runtime data
    └── prod -> ${VERSION}/  # Production symlink

    System links: /usr/local/bin/darkscan -> ${INSTALL_BASE}/prod/bin/darkscan

Examples:
    $0              # Build darkscan
    $0 all          # Build all binaries
    $0 install      # Install all binaries (requires sudo)
    $0 uninstall    # Remove entire installation
    $0 uninstall 1.0.0  # Remove specific version
    $0 clean        # Clean build artifacts

Version Management (after install):
    # Rollback to previous version
    sudo ln -sf /usr/local/darkscan/0.9.0 /usr/local/darkscan/prod

    # Upgrade to new version
    sudo ln -sf /usr/local/darkscan/1.1.0 /usr/local/darkscan/prod

EOF
}

# Main logic
main() {
    case "${1:-build}" in
        build)
            build
            ;;
        all)
            build_all
            ;;
        install)
            install
            ;;
        uninstall)
            shift
            uninstall "$@"
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
