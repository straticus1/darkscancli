package local

import (
	"os"
	"path/filepath"

	"github.com/afterdarktech/darkscan/pkg/fsutil"
	"github.com/afterdarktech/darkscan/pkg/vfs"
)

type LocalFS struct{}

func New() *LocalFS {
	return &LocalFS{}
}

func (l *LocalFS) Open(name string) (vfs.File, error) {
	return os.Open(name)
}

func (l *LocalFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (l *LocalFS) Walk(root string, fn filepath.WalkFunc) error {
	return fsutil.Walk(root, fn)
}

func (l *LocalFS) ListXattrs(path string) ([]string, error) {
	return fsutil.ListXattrs(path)
}

func (l *LocalFS) GetXattr(path string, attr string) ([]byte, error) {
	return fsutil.GetXattr(path, attr)
}
