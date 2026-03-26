//go:build !noclamav && !windows

package main

import (
	"github.com/afterdarktech/darkscan/pkg/clamav"
	"github.com/afterdarktech/darkscan/pkg/scanner"
)

func registerClamAV(s *scanner.Scanner) {
	// Attempt to load system clamav
	eng, err := clamav.New("/var/lib/clamav")
	if err == nil {
		s.RegisterEngine(eng)
	}
}
