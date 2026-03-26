package vfs

import (
	"io"
	"os"
	"path/filepath"
)

// File represents a generic file object read from any VFS backend.
type File interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

// FileSystem represents the interface all VFS backends must implement.
type FileSystem interface {
	// Open opens a file for reading.
	Open(name string) (File, error)

	// Stat returns a FileInfo describing the named file.
	Stat(name string) (os.FileInfo, error)

	// Walk walks the file tree rooted at root, calling fn for each file or directory.
	Walk(root string, fn filepath.WalkFunc) error

	// Extended Attributes / Metadata
	// ListXattrs returns a list of extended attribute names for a generic path
	ListXattrs(path string) ([]string, error)

	// GetXattr returns the value of an extended attribute
	GetXattr(path string, attr string) ([]byte, error)
}
