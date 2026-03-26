//go:build windows

package fsutil

// ListXattrs is a stub for Windows where xattrs are handled differently (typically via ADS)
func ListXattrs(path string) ([]string, error) {
	return nil, nil
}

// GetXattr is a stub for Windows
func GetXattr(path, name string) ([]byte, error) {
	return nil, nil
}
