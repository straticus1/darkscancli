//go:build !windows

package fsutil

// GetAlternateDataStreams is a stub for non-Windows platforms.
// It returns an empty list since NTFS Alternate Data Streams are Windows-specific.
func GetAlternateDataStreams(path string) ([]string, error) {
	return nil, nil
}
