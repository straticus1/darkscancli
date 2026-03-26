//go:build noclamav || windows

package main

import (
	"github.com/afterdarktech/darkscan/pkg/scanner"
)

func registerClamAV(s *scanner.Scanner) {
	// Stub: ClamAV disabled
}
