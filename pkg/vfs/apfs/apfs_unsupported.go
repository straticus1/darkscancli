//go:build !darwin

package apfs

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/afterdarksys/darkscan/pkg/vfs"
)

// ErrUnsupported is returned when someone attempts to use the APFS module on a non-macOS system.
var ErrUnsupported = errors.New("APFS support is only available when compiled for macOS (darwin)")

// ApfsFS implements the vfs.FileSystem interface but safely disables functionality on non-macOS platforms.
type ApfsFS struct {
	volumePath string
}

// New creates a new APFS Virtual File System parser. On this platform, it will return an instance
// that faults all methods with ErrUnsupported.
func New(volumePath string) *ApfsFS {
	return &ApfsFS{
		volumePath: volumePath,
	}
}

// Open immediately returns ErrUnsupported.
func (a *ApfsFS) Open(name string) (vfs.File, error) {
	return nil, ErrUnsupported
}

// Stat immediately returns ErrUnsupported.
func (a *ApfsFS) Stat(name string) (os.FileInfo, error) {
	return nil, ErrUnsupported
}

// Walk immediately returns ErrUnsupported.
func (a *ApfsFS) Walk(root string, fn filepath.WalkFunc) error {
	return ErrUnsupported
}

// ListXattrs immediately returns ErrUnsupported.
func (a *ApfsFS) ListXattrs(path string) ([]string, error) {
	return nil, ErrUnsupported
}

// GetXattr immediately returns ErrUnsupported.
func (a *ApfsFS) GetXattr(path string, attr string) ([]byte, error) {
	return nil, ErrUnsupported
}
