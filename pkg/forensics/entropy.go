package forensics

import (
	"math"
)

// CalculateEntropy calculates the Shannon entropy of a byte slice
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freqs := make([]int, 256)
	for _, b := range data {
		freqs[b]++
	}

	entropy := 0.0
	dataLen := float64(len(data))
	for _, freq := range freqs {
		if freq > 0 {
			prob := float64(freq) / dataLen
			entropy -= prob * math.Log2(prob)
		}
	}

	return entropy
}
