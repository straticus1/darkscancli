package archive

import (
	"context"
	"errors"
)

var ErrEncrypted = errors.New("file is encrypted, password required")

type ExtractedFile struct {
	Name    string
	Path    string
	Size    int64
	IsMem   bool
	Content []byte // If extracted to memory
}

type ExtractOptions struct {
	InMemory         bool
	MaxMemoryMB      int64
	MaxFileSizeMB    int64
	PasswordCallback func(path string) (string, error)
}

type Extractor interface {
	Name() string
	CanHandle(path string) bool
	Extract(ctx context.Context, path string, opts ExtractOptions) ([]ExtractedFile, error)
}

type Manager struct {
	extractors []Extractor
}

func NewManager() *Manager {
	return &Manager{
		extractors: make([]Extractor, 0),
	}
}

func (m *Manager) Register(e Extractor) {
	m.extractors = append(m.extractors, e)
}

func (m *Manager) Extract(ctx context.Context, path string, opts ExtractOptions) ([]ExtractedFile, error) {
	for _, e := range m.extractors {
		if e.CanHandle(path) {
			return e.Extract(ctx, path, opts)
		}
	}
	return nil, nil // No extractor found, not an error just unsupported
}
