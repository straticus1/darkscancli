package privacy

import (
	"os"
	"path/filepath"
	"runtime"
)

// DetectBrowsers detects installed browsers and their data locations
func DetectBrowsers() []Browser {
	browsers := make([]Browser, 0)

	switch runtime.GOOS {
	case "darwin":
		browsers = append(browsers, detectMacBrowsers()...)
	case "windows":
		browsers = append(browsers, detectWindowsBrowsers()...)
	case "linux":
		browsers = append(browsers, detectLinuxBrowsers()...)
	}

	// Mark as detected if profile path exists
	for i := range browsers {
		if _, err := os.Stat(browsers[i].ProfilePath); err == nil {
			browsers[i].Detected = true
		}
	}

	return browsers
}

// detectMacBrowsers detects browsers on macOS
func detectMacBrowsers() []Browser {
	home, _ := os.UserHomeDir()

	return []Browser{
		{
			Name:         "Chrome",
			ProfilePath:  filepath.Join(home, "Library/Application Support/Google/Chrome/Default"),
			CookiePath:   filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Cookies"),
			ExtensionDir: filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
			PrefsFile:    filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Preferences"),
			HistoryDB:    filepath.Join(home, "Library/Application Support/Google/Chrome/Default/History"),
		},
		{
			Name:         "Firefox",
			ProfilePath:  filepath.Join(home, "Library/Application Support/Firefox/Profiles"),
			CookiePath:   "", // Firefox uses multiple profiles, need to scan
			ExtensionDir: "",
			PrefsFile:    "",
			HistoryDB:    "",
		},
		{
			Name:         "Safari",
			ProfilePath:  filepath.Join(home, "Library/Safari"),
			CookiePath:   filepath.Join(home, "Library/Cookies/Cookies.binarycookies"),
			ExtensionDir: filepath.Join(home, "Library/Safari/Extensions"),
			PrefsFile:    filepath.Join(home, "Library/Safari/Preferences.plist"),
			HistoryDB:    filepath.Join(home, "Library/Safari/History.db"),
		},
		{
			Name:         "Edge",
			ProfilePath:  filepath.Join(home, "Library/Application Support/Microsoft Edge/Default"),
			CookiePath:   filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/Cookies"),
			ExtensionDir: filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/Extensions"),
			PrefsFile:    filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/Preferences"),
			HistoryDB:    filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/History"),
		},
		{
			Name:         "Brave",
			ProfilePath:  filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default"),
			CookiePath:   filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies"),
			ExtensionDir: filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
			PrefsFile:    filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences"),
			HistoryDB:    filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/History"),
		},
	}
}

// detectWindowsBrowsers detects browsers on Windows
func detectWindowsBrowsers() []Browser {
	home, _ := os.UserHomeDir()
	appData := filepath.Join(home, "AppData")
	localAppData := filepath.Join(appData, "Local")
	roamingAppData := filepath.Join(appData, "Roaming")

	return []Browser{
		{
			Name:         "Chrome",
			ProfilePath:  filepath.Join(localAppData, "Google/Chrome/User Data/Default"),
			CookiePath:   filepath.Join(localAppData, "Google/Chrome/User Data/Default/Cookies"),
			ExtensionDir: filepath.Join(localAppData, "Google/Chrome/User Data/Default/Extensions"),
			PrefsFile:    filepath.Join(localAppData, "Google/Chrome/User Data/Default/Preferences"),
			HistoryDB:    filepath.Join(localAppData, "Google/Chrome/User Data/Default/History"),
		},
		{
			Name:         "Firefox",
			ProfilePath:  filepath.Join(roamingAppData, "Mozilla/Firefox/Profiles"),
			CookiePath:   "", // Multiple profiles
			ExtensionDir: "",
			PrefsFile:    "",
			HistoryDB:    "",
		},
		{
			Name:         "Edge",
			ProfilePath:  filepath.Join(localAppData, "Microsoft/Edge/User Data/Default"),
			CookiePath:   filepath.Join(localAppData, "Microsoft/Edge/User Data/Default/Cookies"),
			ExtensionDir: filepath.Join(localAppData, "Microsoft/Edge/User Data/Default/Extensions"),
			PrefsFile:    filepath.Join(localAppData, "Microsoft/Edge/User Data/Default/Preferences"),
			HistoryDB:    filepath.Join(localAppData, "Microsoft/Edge/User Data/Default/History"),
		},
		{
			Name:         "Brave",
			ProfilePath:  filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data/Default"),
			CookiePath:   filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data/Default/Cookies"),
			ExtensionDir: filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data/Default/Extensions"),
			PrefsFile:    filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data/Default/Preferences"),
			HistoryDB:    filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data/Default/History"),
		},
		{
			Name:         "Opera",
			ProfilePath:  filepath.Join(roamingAppData, "Opera Software/Opera Stable"),
			CookiePath:   filepath.Join(roamingAppData, "Opera Software/Opera Stable/Cookies"),
			ExtensionDir: filepath.Join(roamingAppData, "Opera Software/Opera Stable/Extensions"),
			PrefsFile:    filepath.Join(roamingAppData, "Opera Software/Opera Stable/Preferences"),
			HistoryDB:    filepath.Join(roamingAppData, "Opera Software/Opera Stable/History"),
		},
	}
}

// detectLinuxBrowsers detects browsers on Linux
func detectLinuxBrowsers() []Browser {
	home, _ := os.UserHomeDir()

	return []Browser{
		{
			Name:         "Chrome",
			ProfilePath:  filepath.Join(home, ".config/google-chrome/Default"),
			CookiePath:   filepath.Join(home, ".config/google-chrome/Default/Cookies"),
			ExtensionDir: filepath.Join(home, ".config/google-chrome/Default/Extensions"),
			PrefsFile:    filepath.Join(home, ".config/google-chrome/Default/Preferences"),
			HistoryDB:    filepath.Join(home, ".config/google-chrome/Default/History"),
		},
		{
			Name:         "Firefox",
			ProfilePath:  filepath.Join(home, ".mozilla/firefox"),
			CookiePath:   "", // Multiple profiles
			ExtensionDir: "",
			PrefsFile:    "",
			HistoryDB:    "",
		},
		{
			Name:         "Chromium",
			ProfilePath:  filepath.Join(home, ".config/chromium/Default"),
			CookiePath:   filepath.Join(home, ".config/chromium/Default/Cookies"),
			ExtensionDir: filepath.Join(home, ".config/chromium/Default/Extensions"),
			PrefsFile:    filepath.Join(home, ".config/chromium/Default/Preferences"),
			HistoryDB:    filepath.Join(home, ".config/chromium/Default/History"),
		},
		{
			Name:         "Brave",
			ProfilePath:  filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default"),
			CookiePath:   filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/Cookies"),
			ExtensionDir: filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/Extensions"),
			PrefsFile:    filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/Preferences"),
			HistoryDB:    filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/History"),
		},
	}
}
