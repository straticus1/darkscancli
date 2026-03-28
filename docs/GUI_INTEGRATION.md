# GUI Integration with darkscand

The `darkscand` daemon provides a comprehensive REST API that allows GUI applications to connect, configure, and control the malware scanner.

## Connection Methods

The daemon supports **two connection methods**:

### 1. Unix Socket (Local GUI)
```
Socket: /var/run/darkscand.sock
Permissions: 0660 (owner and group only)
Best for: Desktop GUI applications running on the same machine
```

### 2. TCP/IP (Network GUI)
```
Default: localhost:8080
Network: 0.0.0.0:8080 (all interfaces)
Best for: Web-based GUIs, remote management, mobile apps
```

## API Endpoints

### 1. Health Check
```http
GET /ping
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-03-28T12:00:00Z"
}
```

**Use Case:** GUI can check if daemon is running and responsive

---

### 2. Status Information
```http
GET /status
```

**Response:**
```json
{
  "status": "running",
  "engines": [
    {
      "name": "ClamAV",
      "version": "1.0.0",
      "enabled": true,
      "signatures": 8500000
    },
    {
      "name": "YARA",
      "version": "4.3.0",
      "enabled": true,
      "rules": 1250
    },
    {
      "name": "Steganography",
      "version": "1.0.0",
      "enabled": true
    }
  ],
  "uptime": "2h45m30s",
  "scans_completed": 1523,
  "threats_detected": 42
}
```

**Use Case:** GUI dashboard showing scanner status and statistics

---

### 3. Update Signatures
```http
POST /update
```

**Response:**
```json
{
  "success": true,
  "engines_updated": ["ClamAV", "YARA"],
  "duration": "45.2s"
}
```

**Use Case:** GUI button to update virus definitions

---

### 4. Scan Local File/Directory
```http
POST /scan/local
Content-Type: application/json

{
  "path": "/path/to/scan",
  "recursive": true
}
```

**Response:**
```json
{
  "success": true,
  "duration": "2.3s",
  "results": [
    {
      "file_path": "/path/to/malware.exe",
      "infected": true,
      "threats": [
        {
          "name": "Trojan.Win32.Generic",
          "severity": "high",
          "description": "Generic trojan detected",
          "engine": "ClamAV"
        }
      ],
      "scan_engine": "ClamAV"
    },
    {
      "file_path": "/path/to/image.jpg",
      "infected": true,
      "threats": [
        {
          "name": "STEGO.LSB",
          "severity": "medium",
          "description": "LSB steganography detected",
          "engine": "Steganography"
        }
      ],
      "scan_engine": "Steganography"
    }
  ]
}
```

**Use Case:** GUI file browser with scan functionality

---

### 5. Scan Uploaded File
```http
POST /scan/stream
Content-Type: multipart/form-data

file: <binary data>
```

**Response:**
```json
{
  "success": true,
  "duration": "0.5s",
  "results": [
    {
      "file_path": "uploaded_file.exe",
      "infected": false,
      "threats": [],
      "scan_engine": "Multi-Engine"
    }
  ]
}
```

**Use Case:** Drag-and-drop file scanning in GUI

---

## GUI Implementation Examples

### JavaScript/Electron Example

```javascript
class DarkScanClient {
  constructor(endpoint = 'http://localhost:8080') {
    this.endpoint = endpoint;
  }

  async ping() {
    const response = await fetch(`${this.endpoint}/ping`);
    return await response.json();
  }

  async getStatus() {
    const response = await fetch(`${this.endpoint}/status`);
    return await response.json();
  }

  async updateSignatures() {
    const response = await fetch(`${this.endpoint}/update`, {
      method: 'POST'
    });
    return await response.json();
  }

  async scanPath(path, recursive = true) {
    const response = await fetch(`${this.endpoint}/scan/local`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, recursive })
    });
    return await response.json();
  }

  async scanFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${this.endpoint}/scan/stream`, {
      method: 'POST',
      body: formData
    });
    return await response.json();
  }
}

// Usage in Electron app
const scanner = new DarkScanClient();

// Check if daemon is running
async function checkDaemon() {
  try {
    const result = await scanner.ping();
    console.log('Daemon is running:', result.status);
    return true;
  } catch (error) {
    console.error('Daemon not running');
    return false;
  }
}

// Scan a directory
async function scanDirectory(path) {
  const result = await scanner.scanPath(path, true);

  if (result.success) {
    const infected = result.results.filter(r => r.infected);
    console.log(`Scanned: ${result.results.length} files`);
    console.log(`Infected: ${infected.length} files`);

    infected.forEach(file => {
      console.log(`⚠️  ${file.file_path}`);
      file.threats.forEach(threat => {
        console.log(`   - ${threat.name}: ${threat.description}`);
      });
    });
  }
}

// Drag-and-drop scanning
dropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];

  const result = await scanner.scanFile(file);

  if (result.results[0].infected) {
    alert('⚠️ THREAT DETECTED!');
  } else {
    alert('✓ File is clean');
  }
});
```

---

### Python/PyQt Example

```python
import requests
import json

class DarkScanClient:
    def __init__(self, endpoint='http://localhost:8080'):
        self.endpoint = endpoint

    def ping(self):
        response = requests.get(f'{self.endpoint}/ping')
        return response.json()

    def get_status(self):
        response = requests.get(f'{self.endpoint}/status')
        return response.json()

    def update_signatures(self):
        response = requests.post(f'{self.endpoint}/update')
        return response.json()

    def scan_path(self, path, recursive=True):
        data = {'path': path, 'recursive': recursive}
        response = requests.post(
            f'{self.endpoint}/scan/local',
            json=data
        )
        return response.json()

    def scan_file(self, file_path):
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(
                f'{self.endpoint}/scan/stream',
                files=files
            )
        return response.json()

# Usage in PyQt application
from PyQt5.QtWidgets import QMainWindow, QPushButton, QFileDialog

class ScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = DarkScanClient()
        self.initUI()

    def initUI(self):
        # Scan button
        scan_btn = QPushButton('Scan File', self)
        scan_btn.clicked.connect(self.scan_file)

        # Update button
        update_btn = QPushButton('Update Signatures', self)
        update_btn.clicked.connect(self.update_signatures)

    def scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self)
        if file_path:
            result = self.scanner.scan_path(file_path, False)

            if result['success'] and result['results']:
                file_result = result['results'][0]
                if file_result['infected']:
                    self.show_threat_dialog(file_result)
                else:
                    self.show_clean_dialog()

    def update_signatures(self):
        result = self.scanner.update_signatures()
        if result['success']:
            self.show_message(f"Updated in {result['duration']}")
```

---

### Swift/macOS Example

```swift
import Foundation

class DarkScanClient {
    let endpoint: String

    init(endpoint: String = "http://localhost:8080") {
        self.endpoint = endpoint
    }

    func ping(completion: @escaping (Result<[String: Any], Error>) -> Void) {
        guard let url = URL(string: "\(endpoint)/ping") else { return }

        URLSession.shared.dataTask(with: url) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            if let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                completion(.success(json))
            }
        }.resume()
    }

    func scanPath(_ path: String, recursive: Bool = true,
                  completion: @escaping (Result<ScanResponse, Error>) -> Void) {
        guard let url = URL(string: "\(endpoint)/scan/local") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = ["path": path, "recursive": recursive] as [String : Any]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { data, response, error in
            // Parse response...
            completion(.success(scanResponse))
        }.resume()
    }
}

// Usage in SwiftUI
struct ContentView: View {
    let scanner = DarkScanClient()
    @State private var scanResults: [ScanResult] = []

    var body: some View {
        VStack {
            Button("Scan Downloads") {
                scanDownloads()
            }

            List(scanResults) { result in
                HStack {
                    Image(systemName: result.infected ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundColor(result.infected ? .red : .green)

                    Text(result.filePath)

                    if result.infected {
                        Text("\(result.threats.count) threats")
                            .foregroundColor(.red)
                    }
                }
            }
        }
    }

    func scanDownloads() {
        let downloadsPath = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0].path

        scanner.scanPath(downloadsPath) { result in
            switch result {
            case .success(let response):
                DispatchQueue.main.async {
                    self.scanResults = response.results
                }
            case .failure(let error):
                print("Scan failed: \(error)")
            }
        }
    }
}
```

---

## Configuration API (Future Enhancement)

While not yet implemented, the daemon can be extended with configuration endpoints:

```http
# Get current configuration
GET /config

# Update configuration
POST /config
{
  "max_file_size": 100,
  "scan_archives": true,
  "engines": {
    "clamav": { "enabled": true },
    "yara": { "enabled": true },
    "stego": { "enabled": false }
  }
}

# Add custom YARA rule
POST /config/rules/yara
Content-Type: application/json

{
  "name": "custom_rule",
  "rule": "rule CustomMalware { ... }"
}
```

---

## Real-time Scanning (WebSocket)

For live scanning updates, a WebSocket endpoint can be added:

```javascript
const ws = new WebSocket('ws://localhost:8080/scan/watch');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);

  if (update.type === 'scan_start') {
    console.log(`Scanning: ${update.path}`);
  } else if (update.type === 'threat_detected') {
    console.log(`⚠️ Threat: ${update.file}`);
    showNotification(update);
  } else if (update.type === 'scan_complete') {
    console.log(`Complete: ${update.files_scanned} files`);
  }
};

// Send scan request
ws.send(JSON.stringify({
  action: 'scan',
  path: '/path/to/scan',
  recursive: true
}));
```

---

## Security Considerations

### Authentication (Recommended for Production)

```javascript
// Add API key authentication
const scanner = new DarkScanClient('http://localhost:8080');
scanner.setApiKey('your-api-key-here');

// All requests include auth header
headers: {
  'Authorization': 'Bearer your-api-key-here'
}
```

### HTTPS/TLS (For Remote Access)

```bash
# Run daemon with TLS
darkscand --listen 0.0.0.0:8443 \
          --tls-cert /path/to/cert.pem \
          --tls-key /path/to/key.pem
```

### Rate Limiting

The daemon should implement rate limiting to prevent abuse:
- Max 100 requests per minute per IP
- Max 10 concurrent scans

---

## Example GUI Features

A complete GUI should provide:

1. **Dashboard**
   - Daemon status indicator
   - Recent scans list
   - Threat statistics
   - Engine status (ClamAV, YARA, Stego)

2. **File Scanner**
   - Drag-and-drop scanning
   - File browser with right-click scan
   - Batch scanning
   - Progress indicators

3. **Scheduled Scans**
   - Configure recurring scans
   - Scan specific directories automatically
   - Email/notification on threats

4. **Quarantine Management**
   - View quarantined files
   - Restore/delete files
   - Whitelist management

5. **Settings**
   - Enable/disable engines
   - Update signatures
   - Configure exclusions
   - Set scan preferences

6. **Logs & Reports**
   - Scan history
   - Threat timeline
   - Export reports (PDF, JSON)

---

## Starting the Daemon for GUI Access

```bash
# Start daemon with both Unix socket (for local CLI) and TCP (for GUI)
darkscand --listen localhost:8080 \
          --socket /var/run/darkscand.sock \
          --log-file /var/log/darkscand.log

# For network access (be careful with security!)
darkscand --listen 0.0.0.0:8080

# With custom settings
darkscand --listen localhost:8080 \
          --max-upload 1000 \
          --workers 8
```

---

## Testing the API

```bash
# Test with curl
curl http://localhost:8080/ping

curl http://localhost:8080/status

curl -X POST http://localhost:8080/scan/local \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/test", "recursive": true}'

curl -X POST http://localhost:8080/scan/stream \
  -F "file=@suspicious.exe"
```

---

## Summary

✅ The daemon provides a **REST API** that any GUI can use
✅ Supports **Unix socket** (local) and **TCP/IP** (network)
✅ **JSON responses** for easy parsing
✅ Works with **Electron, PyQt, Swift, React, Vue, etc.**
✅ **No authentication required** for local socket (secure)
✅ **Lightweight and fast** - perfect for desktop/mobile GUIs

Your GUI can connect to `darkscand` and have full control over scanning, updating, and monitoring!
