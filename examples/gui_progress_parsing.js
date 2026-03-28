// Example: How a GUI can parse darkscan progress output
// This works with Electron, Tauri, or any Node.js-based GUI

const { spawn } = require('child_process');
const readline = require('readline');

class DarkScanProgress {
  constructor() {
    this.listeners = {
      scan_start: [],
      file_scanning: [],
      file_scanned: [],
      threat_detected: [],
      scan_complete: [],
      scan_error: []
    };
  }

  // Register event listeners
  on(event, callback) {
    if (this.listeners[event]) {
      this.listeners[event].push(callback);
    }
  }

  // Emit events to all listeners
  emit(event, data) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(cb => cb(data));
    }
  }

  // Start a scan with progress monitoring
  scan(path, options = {}) {
    return new Promise((resolve, reject) => {
      const args = ['scan', path, '--progress'];

      // Add optional flags
      if (options.recursive !== false) args.push('--recursive');
      if (options.yara) args.push('--yara');
      if (options.capa) args.push('--capa');
      if (options.quarantine) args.push('--quarantine');

      // Spawn darkscan process
      const darkscan = spawn('darkscan', args);

      let results = [];
      let error = null;

      // Parse stderr for progress events (JSON lines)
      const stderrReader = readline.createInterface({
        input: darkscan.stderr,
        crlfDelay: Infinity
      });

      stderrReader.on('line', (line) => {
        try {
          const event = JSON.parse(line);

          // Emit to listeners
          this.emit(event.type, event.data);

        } catch (err) {
          // Not JSON, might be regular stderr output
          console.error('STDERR:', line);
        }
      });

      // Capture stdout for final results
      const stdoutReader = readline.createInterface({
        input: darkscan.stdout,
        crlfDelay: Infinity
      });

      stdoutReader.on('line', (line) => {
        results.push(line);
      });

      // Handle process completion
      darkscan.on('close', (code) => {
        if (code === 0) {
          resolve({ code, results });
        } else {
          reject({ code, error: error || `Process exited with code ${code}` });
        }
      });

      darkscan.on('error', (err) => {
        error = err.message;
        reject(err);
      });
    });
  }
}

// Usage Example 1: Simple progress bar in terminal
function simpleExample() {
  const scanner = new DarkScanProgress();

  scanner.on('scan_start', (data) => {
    console.log(`Starting scan of: ${data.path}`);
    console.log(`Total files: ${data.total_files}`);
  });

  scanner.on('file_scanned', (data) => {
    const { progress } = data;
    const bar = '█'.repeat(Math.floor(progress.percentage / 2));
    const empty = '░'.repeat(50 - Math.floor(progress.percentage / 2));

    process.stdout.write(`\r[${bar}${empty}] ${progress.percentage.toFixed(1)}% (${progress.scanned}/${progress.total})`);

    if (data.infected) {
      console.log(`\n⚠️  THREAT: ${data.file}`);
      data.threats.forEach(threat => {
        console.log(`   - ${threat.name}: ${threat.description}`);
      });
    }
  });

  scanner.on('scan_complete', (data) => {
    console.log(`\n\n✓ Scan complete!`);
    console.log(`  Scanned: ${data.total_scanned} files`);
    console.log(`  Threats: ${data.threats_found}`);
    console.log(`  Duration: ${data.duration.toFixed(2)}s`);
  });

  // Start scan
  scanner.scan('/path/to/scan', { recursive: true, yara: true })
    .then(result => console.log('Scan finished'))
    .catch(err => console.error('Scan failed:', err));
}

// Usage Example 2: React/Electron GUI with state management
class ScannerGUI {
  constructor() {
    this.scanner = new DarkScanProgress();
    this.state = {
      scanning: false,
      progress: 0,
      scanned: 0,
      total: 0,
      threats: [],
      currentFile: '',
      eta: 0
    };
  }

  setupProgressHandlers(updateUI) {
    this.scanner.on('scan_start', (data) => {
      this.state = {
        scanning: true,
        progress: 0,
        scanned: 0,
        total: data.total_files,
        threats: [],
        currentFile: '',
        eta: 0
      };
      updateUI(this.state);
    });

    this.scanner.on('file_scanning', (data) => {
      this.state.currentFile = data.file;
      this.state.progress = data.progress.percentage;
      this.state.scanned = data.progress.scanned;
      this.state.eta = data.progress.eta;
      updateUI(this.state);
    });

    this.scanner.on('threat_detected', (data) => {
      this.state.threats.push({
        file: data.file,
        threats: data.threats,
        timestamp: new Date()
      });
      updateUI(this.state);

      // Show notification
      this.showThreatNotification(data);
    });

    this.scanner.on('scan_complete', (data) => {
      this.state.scanning = false;
      this.state.progress = 100;
      updateUI(this.state);

      this.showCompletionDialog(data);
    });
  }

  startScan(path, options) {
    return this.scanner.scan(path, options);
  }

  showThreatNotification(data) {
    // Electron notification
    new Notification('Threat Detected!', {
      body: `${data.threats.length} threat(s) found in ${data.file}`,
      icon: 'warning-icon.png'
    });
  }

  showCompletionDialog(data) {
    // Show results dialog
    console.log('Scan complete:', data);
  }
}

// Usage Example 3: Real-time WebSocket forwarding (for web dashboard)
class WebSocketProgressForwarder {
  constructor(wsServer) {
    this.scanner = new DarkScanProgress();
    this.wsServer = wsServer;

    // Forward all events to connected WebSocket clients
    ['scan_start', 'file_scanning', 'file_scanned', 'threat_detected', 'scan_complete', 'scan_error']
      .forEach(event => {
        this.scanner.on(event, (data) => {
          this.wsServer.broadcast(JSON.stringify({
            type: event,
            data: data,
            timestamp: new Date()
          }));
        });
      });
  }

  startScan(path, options) {
    return this.scanner.scan(path, options);
  }
}

// Usage Example 4: Progress bar with ETA
function advancedProgressBar() {
  const scanner = new DarkScanProgress();

  scanner.on('file_scanned', (data) => {
    const { progress } = data;

    // Create visual progress bar
    const width = 50;
    const filled = Math.floor(progress.percentage / 100 * width);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);

    // Format ETA
    const eta = progress.eta > 0 ? formatDuration(progress.eta) : 'calculating...';

    // Format threats count with color
    const threatsDisplay = progress.threats > 0
      ? `\x1b[31m${progress.threats} threats\x1b[0m`
      : `\x1b[32m0 threats\x1b[0m`;

    process.stdout.write(
      `\r[${bar}] ${progress.percentage.toFixed(1)}% ` +
      `(${progress.scanned}/${progress.total}) ` +
      `${threatsDisplay} ` +
      `ETA: ${eta}`
    );
  });

  scanner.scan('/path/to/scan', { recursive: true });
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${(seconds % 60).toFixed(0)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

// Export for use in GUI applications
module.exports = { DarkScanProgress, ScannerGUI, WebSocketProgressForwarder };

/*
 * EXAMPLE JSON OUTPUT:
 *
 * {"type":"scan_start","timestamp":"2024-03-28T12:00:00Z","data":{"path":"/home/user/downloads","total_files":1523}}
 * {"type":"file_scanning","timestamp":"2024-03-28T12:00:01Z","data":{"file":"/home/user/downloads/file1.pdf","progress":{"scanned":1,"total":1523,"percentage":0.07,"threats":0,"elapsed":1.2,"eta":1800}}}
 * {"type":"file_scanned","timestamp":"2024-03-28T12:00:01Z","data":{"file":"/home/user/downloads/file1.pdf","infected":false,"progress":{"scanned":1,"total":1523,"percentage":0.07,"threats":0,"elapsed":1.2,"eta":1800}}}
 * {"type":"threat_detected","timestamp":"2024-03-28T12:05:23Z","data":{"file":"/home/user/downloads/malware.exe","threats":[{"name":"Trojan.Win32.Generic","severity":"high","description":"Generic trojan detected","engine":"ClamAV"}]}}
 * {"type":"scan_complete","timestamp":"2024-03-28T12:30:00Z","data":{"total_scanned":1523,"threats_found":3,"duration":1800.5,"clean_files":1520}}
 */
