//go:build windows

package fsutil

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstStreamW = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modkernel32.NewProc("FindNextStreamW")
)

type WIN32_FIND_STREAM_DATA struct {
	StreamSize int64
	StreamName [296]uint16
}

const FindStreamInfoStandard = 0

// GetAlternateDataStreams enumerates NTFS Alternate Data Streams for a given file.
func GetAlternateDataStreams(path string) ([]string, error) {
	path16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var data WIN32_FIND_STREAM_DATA
	handle, _, _ := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(path16)),
		uintptr(FindStreamInfoStandard),
		uintptr(unsafe.Pointer(&data)),
		0,
	)

	if handle == ^uintptr(0) {
		return nil, nil
	}
	defer syscall.FindClose(syscall.Handle(handle))

	var streams []string
	for {
		name := syscall.UTF16ToString(data.StreamName[:])
		if name != "::$DATA" {
			streams = append(streams, name)
		}

		ret, _, _ := procFindNextStreamW.Call(
			handle,
			uintptr(unsafe.Pointer(&data)),
		)
		if ret == 0 {
			break
		}
	}

	return streams, nil
}
