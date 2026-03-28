package scanner

import "context"

// Middleware allows intercepting and modifying scan operations.
// Middlewares are executed in the order they are registered.
type Middleware interface {
	// PreScan is called before scanning a file or stream.
	// The path argument is the file path or stream identifier.
	// If it returns a non-nil slice (even an empty one), the scan is bypassed
	// and the middleware's results are returned immediately.
	PreScan(ctx context.Context, path string) ([]*ScanResult, error)

	// PostScan is called after a scan completes.
	// It allows the middleware to process the results (e.g., caching, alerting).
	PostScan(ctx context.Context, path string, results []*ScanResult) error
}
