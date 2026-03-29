//go:build darwin

package apfs

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/afterdarksys/darkscan/pkg/vfs"
)

// ApfsFS implements the vfs.FileSystem interface for Apple's APFS volumes.
// This is the active implementation compiled only on macOS.
type ApfsFS struct {
	volumePath string
}

// New creates a new APFS Virtual File System parser bound to a specific volume or image path.
func New(volumePath string) *ApfsFS {
	return &ApfsFS{
		volumePath: volumePath,
	}
}

// Open opens a file for reading from the APFS volume.
func (a *ApfsFS) Open(name string) (vfs.File, error) {
	// TODO: Implement actual APFS CGO/pure-go file extraction here
	return nil, errors.New("APFS Open not yet fully implemented")
}

// Stat returns a FileInfo describing the named file within the APFS structure.
func (a *ApfsFS) Stat(name string) (os.FileInfo, error) {
	// TODO: Implement actual APFS metadata parsing
	return nil, errors.New("APFS Stat not yet fully implemented")
}

// Walk walks the file tree rooted at root within the APFS volume.
func (a *ApfsFS) Walk(root string, fn filepath.WalkFunc) error {
	// TODO: Implement APFS B-tree / catalog enumeration
	return errors.New("APFS Walk not yet fully implemented")
}

// ListXattrs returns a list of extended attribute names for an APFS path.
func (a *ApfsFS) ListXattrs(path string) ([]string, error) {
	// TODO: Implement APFS xattr parsing
	return nil, errors.New("APFS ListXattrs not yet fully implemented")
}

// GetXattr returns the value of an extended attribute from an APFS path.
func (a *ApfsFS) GetXattr(path string, attr string) ([]byte, error) {
	// TODO: Implement APFS xattr parsing
	return nil, errors.New("APFS GetXattr not yet fully implemented")
}
