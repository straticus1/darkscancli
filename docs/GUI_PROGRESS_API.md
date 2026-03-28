# GUI Progress API

The `--progress` flag enables darkscan to output JSON progress events to stderr, allowing GUIs to display real-time progress bars and scan status.

## Usage

```bash
darkscan scan /path/to/scan --progress
```

## Output Format

Progress events are output as JSON lines to **stderr** (not stdout). This allows stdout to remain clean for final results while stderr streams progress updates.

### Event Types

#### 1. scan_start
Emitted when a scan begins.

```json
{
  "type": "scan_start",
  "timestamp": "2024-03-28T12:00:00Z",
  "data": {
    "path": "/home/user/downloads",
    "total_files": 1523
  }
}
```

#### 2. file_scanning
Emitted when a file is about to be scanned.

```json
{
  "type": "file_scanning",
  "timestamp": "2024-03-28T12:00:01Z",
  "data": {
    "file": "/home/user/downloads/document.pdf",
    "progress": {
      "scanned": 1,
      "total": 1523,
      "percentage": 0.07,
      "threats": 0,
      "elapsed": 1.2,
      "eta": 1800.0
    }
  }
}
```

#### 3. file_scanned
Emitted after a file has been scanned.

```json
{
  "type": "file_scanned",
  "timestamp": "2024-03-28T12:00:01.5Z",
  "data": {
    "file": "/home/user/downloads/document.pdf",
    "infected": false,
    "progress": {
      "scanned": 1,
      "total": 1523,
      "percentage": 0.07,
      "threats": 0,
      "elapsed": 1.2,
      "eta": 1800.0
    }
  }
}
```

#### 4. threat_detected
Emitted when a threat is found (for real-time alerts).

```json
{
  "type": "threat_detected",
  "timestamp": "2024-03-28T12:05:23Z",
  "data": {
    "file": "/home/user/downloads/malware.exe",
    "threats": [
      {
        "name": "Trojan.Win32.Generic",
        "severity": "high",
        "description": "Generic trojan detected",
        "engine": "ClamAV"
      }
    ]
  }
}
```

#### 5. scan_complete
Emitted when the scan finishes.

```json
{
  "type": "scan_complete",
  "timestamp": "2024-03-28T12:30:00Z",
  "data": {
    "total_scanned": 1523,
    "threats_found": 3,
    "duration": 1800.5,
    "clean_files": 1520
  }
}
```

#### 6. scan_error
Emitted when an error occurs during scanning.

```json
{
  "type": "scan_error",
  "timestamp": "2024-03-28T12:10:15Z",
  "data": {
    "file": "/home/user/downloads/corrupted.zip",
    "error": "permission denied"
  }
}
```

## Progress Data Fields

The `progress` object contains:

- **scanned** (int): Number of files scanned so far
- **total** (int): Total number of files to scan
- **percentage** (float): Completion percentage (0-100)
- **threats** (int): Number of threats detected so far
- **elapsed** (float): Time elapsed in seconds
- **eta** (float): Estimated time remaining in seconds

## Implementation Examples

### JavaScript/Node.js (Electron, Tauri)

```javascript
const { spawn } = require('child_process');
const readline = require('readline');

function scanWithProgress(path, onProgress) {
  const darkscan = spawn('darkscan', ['scan', path, '--progress']);

  const stderrReader = readline.createInterface({
    input: darkscan.stderr,
    crlfDelay: Infinity
  });

  stderrReader.on('line', (line) => {
    try {
      const event = JSON.parse(line);
      onProgress(event);
    } catch (err) {
      // Not JSON, regular stderr
    }
  });

  return darkscan;
}

// Usage
scanWithProgress('/path/to/scan', (event) => {
  if (event.type === 'file_scanned') {
    updateProgressBar(event.data.progress.percentage);
  }
  else if (event.type === 'threat_detected') {
    showThreatAlert(event.data);
  }
});
```

### Python (PyQt, tkinter)

```python
import subprocess
import json
import threading

def scan_with_progress(path, on_event):
    proc = subprocess.Popen(
        ['darkscan', 'scan', path, '--progress'],
        stderr=subprocess.PIPE,
        text=True
    )

    for line in proc.stderr:
        try:
            event = json.loads(line.strip())
            on_event(event)
        except json.JSONDecodeError:
            pass

# Usage
def handle_event(event):
    if event['type'] == 'file_scanned':
        update_progress_bar(event['data']['progress']['percentage'])
    elif event['type'] == 'threat_detected':
        show_threat_alert(event['data'])

threading.Thread(
    target=lambda: scan_with_progress('/path/to/scan', handle_event),
    daemon=True
).start()
```

### Swift (macOS)

```swift
import Foundation

class DarkScanProgress {
    let process = Process()
    var onEvent: ((Event) -> Void)?

    func scan(path: String) {
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/darkscan")
        process.arguments = ["scan", path, "--progress"]

        let pipe = Pipe()
        process.standardError = pipe

        process.launch()

        let handle = pipe.fileHandleForReading
        handle.readabilityHandler = { handle in
            let data = handle.availableData
            guard let line = String(data: data, encoding: .utf8) else { return }

            if let jsonData = line.data(using: .utf8),
               let event = try? JSONDecoder().decode(Event.self, from: jsonData) {
                self.onEvent?(event)
            }
        }
    }
}

// Usage
let scanner = DarkScanProgress()
scanner.onEvent = { event in
    if event.type == "file_scanned" {
        updateProgressBar(event.data.progress.percentage)
    }
}
scanner.scan(path: "/path/to/scan")
```

## GUI Integration Patterns

### Pattern 1: Progress Bar

```javascript
scanner.on('file_scanned', (data) => {
  const percentage = data.progress.percentage;
  progressBar.setValue(percentage);
  statusLabel.setText(`Scanned ${data.progress.scanned}/${data.progress.total}`);
});
```

### Pattern 2: Real-time Threat List

```javascript
scanner.on('threat_detected', (data) => {
  const item = createListItem({
    file: data.file,
    threats: data.threats,
    timestamp: new Date()
  });
  threatsList.append(item);
  showNotification('Threat Detected!', data.file);
});
```

### Pattern 3: ETA Display

```javascript
scanner.on('file_scanned', (data) => {
  const eta = data.progress.eta;
  const etaText = formatDuration(eta); // e.g., "5m 23s"
  etaLabel.setText(`ETA: ${etaText}`);
});
```

### Pattern 4: Statistics Dashboard

```javascript
let stats = { total: 0, clean: 0, threats: 0 };

scanner.on('file_scanned', (data) => {
  stats.total = data.progress.scanned;
  stats.threats = data.progress.threats;
  stats.clean = stats.total - stats.threats;

  updateDashboard(stats);
});
```

## Performance Considerations

- Events are emitted to stderr, so they don't interfere with stdout results
- Each event is a single JSON line (newline-delimited JSON)
- Events are emitted in real-time as scanning progresses
- No buffering delays - perfect for responsive GUIs

## Error Handling

```javascript
stderrReader.on('line', (line) => {
  try {
    const event = JSON.parse(line);
    handleEvent(event);
  } catch (err) {
    // Line is not JSON - might be error message
    console.error('Scanner message:', line);
  }
});
```

## Complete Examples

See the examples directory:
- `examples/gui_progress_parsing.js` - Node.js/Electron example with React components
- `examples/gui_progress_parsing.py` - Python example with PyQt5 and tkinter

## Compatibility

Works with:
- ✅ Electron apps
- ✅ Tauri apps
- ✅ PyQt/PySide
- ✅ tkinter
- ✅ Swift/SwiftUI
- ✅ Web apps (via WebSocket relay)
- ✅ Any language that can spawn processes and read stderr

## Tips

1. **Parse stderr line-by-line**: Each event is a single JSON line
2. **Use threads/async**: Don't block the UI thread while scanning
3. **Buffer updates**: Update UI at most 60fps to avoid lag
4. **Handle errors**: Not all stderr lines are JSON events
5. **Show ETA**: Users love knowing how long is left
6. **Highlight threats**: Make threats visually prominent
7. **Play sounds**: Audio alerts for threat detection
8. **Show notifications**: System notifications for important events
