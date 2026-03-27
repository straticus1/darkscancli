package rules

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// YARARepository represents a YARA rule repository
type YARARepository struct {
	Name        string
	URL         string
	Description string
	Enabled     bool
}

// YARAManager manages YARA rule repositories
type YARAManager struct {
	rulesDir     string
	repositories []YARARepository
}

// Popular YARA rule repositories
var DefaultRepositories = []YARARepository{
	{
		Name:        "yara-rules",
		URL:         "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
		Description: "Community YARA rules collection",
		Enabled:     true,
	},
	{
		Name:        "awesome-yara",
		URL:         "https://github.com/InQuest/awesome-yara/archive/refs/heads/master.zip",
		Description: "Curated list of YARA rules and tools",
		Enabled:     false,
	},
	{
		Name:        "signature-base",
		URL:         "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
		Description: "Florian Roth's signature base",
		Enabled:     false,
	},
}

// NewYARAManager creates a new YARA rule manager
func NewYARAManager(rulesDir string) (*YARAManager, error) {
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %w", err)
	}

	return &YARAManager{
		rulesDir:     rulesDir,
		repositories: DefaultRepositories,
	}, nil
}

// DownloadRepository downloads and extracts YARA rules from a repository
func (ym *YARAManager) DownloadRepository(repo YARARepository) error {
	fmt.Printf("Downloading %s...\n", repo.Name)

	// Create temp file for download
	tmpFile, err := os.CreateTemp("", "yara-rules-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Download the repository
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Get(repo.URL)
	if err != nil {
		return fmt.Errorf("failed to download repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Write to temp file
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write download: %w", err)
	}

	tmpFile.Close()

	// Extract the archive
	destDir := filepath.Join(ym.rulesDir, repo.Name)
	if err := os.RemoveAll(destDir); err != nil {
		return fmt.Errorf("failed to remove old rules: %w", err)
	}

	if err := extractZip(tmpFile.Name(), destDir); err != nil {
		return fmt.Errorf("failed to extract rules: %w", err)
	}

	fmt.Printf("Successfully downloaded %s to %s\n", repo.Name, destDir)
	return nil
}

// UpdateAll updates all enabled repositories
func (ym *YARAManager) UpdateAll() error {
	for _, repo := range ym.repositories {
		if !repo.Enabled {
			continue
		}

		if err := ym.DownloadRepository(repo); err != nil {
			fmt.Printf("Warning: Failed to update %s: %v\n", repo.Name, err)
		}
	}
	return nil
}

// ListRepositories returns available repositories
func (ym *YARAManager) ListRepositories() []YARARepository {
	return ym.repositories
}

// GetInstalledRules returns a list of installed rule files
func (ym *YARAManager) GetInstalledRules() ([]string, error) {
	var rules []string

	err := filepath.Walk(ym.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara")) {
			rules = append(rules, path)
		}

		return nil
	})

	return rules, err
}

// GetRuleCount returns the number of installed rules
func (ym *YARAManager) GetRuleCount() (int, error) {
	rules, err := ym.GetInstalledRules()
	return len(rules), err
}

// Helper function to extract zip files
func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(dest, 0755)

	for _, f := range r.File {
		// Check for zip slip vulnerability
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0755)
			continue
		}

		// Create directory for file
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		// Extract file
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

// RemoveRepository removes downloaded rules for a repository
func (ym *YARAManager) RemoveRepository(repoName string) error {
	repoDir := filepath.Join(ym.rulesDir, repoName)
	if err := os.RemoveAll(repoDir); err != nil {
		return fmt.Errorf("failed to remove repository: %w", err)
	}
	return nil
}
