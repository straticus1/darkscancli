package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ScanProfile represents a saved scan configuration
type ScanProfile struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Recursive        bool   `json:"recursive"`
	EnableClamAV     bool   `json:"enable_clamav"`
	EnableYARA       bool   `json:"enable_yara"`
	EnableCAPA       bool   `json:"enable_capa"`
	EnableViper      bool   `json:"enable_viper"`
	EnableDocument   bool   `json:"enable_document"`
	EnableHeuristics bool   `json:"enable_heuristics"`
	AutoQuarantine   bool   `json:"auto_quarantine"`
	YARARulesPath    string `json:"yara_rules_path"`
	CAPARulesPath    string `json:"capa_rules_path"`
}

// Manager manages scan profiles
type Manager struct {
	profilesDir string
}

// Built-in profiles
var BuiltInProfiles = map[string]ScanProfile{
	"quick": {
		Name:             "quick",
		Description:      "Quick scan with ClamAV only",
		Recursive:        true,
		EnableClamAV:     true,
		EnableYARA:       false,
		EnableCAPA:       false,
		EnableViper:      false,
		EnableDocument:   true,
		EnableHeuristics: false,
		AutoQuarantine:   false,
	},
	"thorough": {
		Name:             "thorough",
		Description:      "Thorough scan with all engines",
		Recursive:        true,
		EnableClamAV:     true,
		EnableYARA:       true,
		EnableCAPA:       true,
		EnableViper:      false,
		EnableDocument:   true,
		EnableHeuristics: true,
		AutoQuarantine:   false,
	},
	"forensic": {
		Name:             "forensic",
		Description:      "Deep forensic analysis",
		Recursive:        true,
		EnableClamAV:     true,
		EnableYARA:       true,
		EnableCAPA:       true,
		EnableViper:      true,
		EnableDocument:   true,
		EnableHeuristics: true,
		AutoQuarantine:   false,
	},
	"safe": {
		Name:             "safe",
		Description:      "Safe scan with auto-quarantine",
		Recursive:        true,
		EnableClamAV:     true,
		EnableYARA:       true,
		EnableCAPA:       false,
		EnableViper:      false,
		EnableDocument:   true,
		EnableHeuristics: true,
		AutoQuarantine:   true,
	},
}

// NewManager creates a new profile manager
func NewManager(profilesDir string) (*Manager, error) {
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create profiles directory: %w", err)
	}

	return &Manager{
		profilesDir: profilesDir,
	}, nil
}

// Save saves a scan profile
func (m *Manager) Save(profile ScanProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	// Check if it's a built-in profile
	if _, ok := BuiltInProfiles[profile.Name]; ok {
		return fmt.Errorf("cannot override built-in profile: %s", profile.Name)
	}

	profilePath := filepath.Join(m.profilesDir, profile.Name+".json")

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(profilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	return nil
}

// Load loads a scan profile by name
func (m *Manager) Load(name string) (*ScanProfile, error) {
	// Check built-in profiles first
	if profile, ok := BuiltInProfiles[name]; ok {
		return &profile, nil
	}

	// Load custom profile
	profilePath := filepath.Join(m.profilesDir, name+".json")

	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	var profile ScanProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile: %w", err)
	}

	return &profile, nil
}

// List returns all available profiles (built-in + custom)
func (m *Manager) List() ([]ScanProfile, error) {
	profiles := make([]ScanProfile, 0)

	// Add built-in profiles
	for _, profile := range BuiltInProfiles {
		profiles = append(profiles, profile)
	}

	// Add custom profiles
	files, err := os.ReadDir(m.profilesDir)
	if err != nil {
		return profiles, nil // Return built-in profiles even if custom dir doesn't exist
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		name := file.Name()[:len(file.Name())-5] // Remove .json extension
		profile, err := m.Load(name)
		if err != nil {
			continue
		}

		profiles = append(profiles, *profile)
	}

	return profiles, nil
}

// Delete deletes a custom profile
func (m *Manager) Delete(name string) error {
	// Prevent deletion of built-in profiles
	if _, ok := BuiltInProfiles[name]; ok {
		return fmt.Errorf("cannot delete built-in profile: %s", name)
	}

	profilePath := filepath.Join(m.profilesDir, name+".json")
	if err := os.Remove(profilePath); err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	return nil
}
