package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type TarExtractor struct{}

func (t *TarExtractor) Name() string {
	return "TAR"
}

func (t *TarExtractor) CanHandle(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".tar"
}

func (t *TarExtractor) Extract(ctx context.Context, path string, opts ExtractOptions) ([]ExtractedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var extracted []ExtractedFile
	maxBytes := opts.MaxFileSizeMB * 1024 * 1024

	for {
		select {
		case <-ctx.Done():
			return extracted, ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return extracted, err
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue // Skip directories, links, etc
		}

		if strings.Contains(hdr.Name, "..") {
			continue // Tar slip protection
		}

		lr := io.LimitReader(tr, maxBytes)

		if opts.InMemory && hdr.Size < (opts.MaxMemoryMB*1024*1024) {
			buf := new(bytes.Buffer)
			_, err := io.Copy(buf, lr)
			if err != nil {
				continue
			}
			extracted = append(extracted, ExtractedFile{
				Name:    hdr.Name,
				Size:    int64(buf.Len()),
				IsMem:   true,
				Content: buf.Bytes(),
			})
		} else {
			tmpFile, err := os.CreateTemp("", "darkscan-ext-*")
			if err != nil {
				continue
			}
			_, err = io.Copy(tmpFile, lr)
			tmpFile.Close()
			if err != nil {
				os.Remove(tmpFile.Name())
				continue
			}
			extracted = append(extracted, ExtractedFile{
				Name:  hdr.Name,
				Path:  tmpFile.Name(),
				Size:  hdr.Size,
				IsMem: false,
			})
		}
	}

	return extracted, nil
}
