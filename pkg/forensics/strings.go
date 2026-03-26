package forensics

import (
	"strings"
)

// ExtractStrings extracts printable ASCII strings and maps them to behavioral indicators
func ExtractStrings(data []byte, feats *FileFeatures) {
	var current strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			current.WriteByte(b)
		} else {
			if current.Len() >= 4 {
				str := current.String()
				analyzeString(str, feats)
				feats.StringsCount++
			}
			current.Reset()
		}
	}
	// process last string
	if current.Len() >= 4 {
		str := current.String()
		analyzeString(str, feats)
		feats.StringsCount++
	}
}

func analyzeString(s string, feats *FileFeatures) {
	sLower := strings.ToLower(s)

	// Network
	if strings.Contains(sLower, "socket") || strings.Contains(sLower, "connect") || strings.Contains(sLower, "internetopen") || strings.Contains(sLower, "http://") || strings.Contains(sLower, "https://") {
		feats.HasNetworkCalls = true
	}

	// Injection
	if strings.Contains(sLower, "virtualallocex") || strings.Contains(sLower, "writeprocessmemory") || strings.Contains(sLower, "createremotethread") {
		feats.HasInjection = true
	}

	// Evasion
	if strings.Contains(sLower, "isdebuggerpresent") || strings.Contains(sLower, "ntqueryinformationprocess") {
		feats.HasEvasion = true
	}

	// Persistence
	if strings.Contains(sLower, "software\\microsoft\\windows\\currentversion\\run") || strings.Contains(sLower, "schtasks") {
		feats.HasPersistence = true
	}

	// Crypto
	if strings.Contains(sLower, "cryptencrypt") || strings.Contains(sLower, "bcrypt") {
		feats.HasCrypto = true
	}
}
