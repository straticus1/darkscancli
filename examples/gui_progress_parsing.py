#!/usr/bin/env python3
"""
Example: How a Python GUI can parse darkscan progress output
Works with PyQt5, PyQt6, tkinter, or any Python GUI framework
"""

import json
import subprocess
import threading
from typing import Callable, Dict, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProgressData:
    """Container for progress information"""
    scanned: int = 0
    total: int = 0
    percentage: float = 0.0
    threats: int = 0
    elapsed: float = 0.0
    eta: float = 0.0


class DarkScanProgress:
    """Progress parser for darkscan CLI"""

    def __init__(self):
        self.callbacks = {
            'scan_start': [],
            'file_scanning': [],
            'file_scanned': [],
            'threat_detected': [],
            'scan_complete': [],
            'scan_error': []
        }
        self.process = None

    def on(self, event: str, callback: Callable):
        """Register an event callback"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)

    def emit(self, event: str, data: Dict[str, Any]):
        """Emit an event to all registered callbacks"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                callback(data)

    def scan(self, path: str, **options):
        """
        Start a scan with progress monitoring

        Args:
            path: Path to scan
            **options: Scan options (recursive, yara, capa, quarantine, etc.)
        """
        args = ['darkscan', 'scan', path, '--progress']

        # Add optional flags
        if options.get('recursive', True):
            args.append('--recursive')
        if options.get('yara'):
            args.append('--yara')
        if options.get('capa'):
            args.append('--capa')
        if options.get('quarantine'):
            args.append('--quarantine')
        if options.get('profile'):
            args.extend(['--profile', options['profile']])

        # Start process
        self.process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        # Start thread to read progress from stderr
        threading.Thread(target=self._read_progress, daemon=True).start()

        return self.process

    def _read_progress(self):
        """Read and parse progress events from stderr"""
        if not self.process:
            return

        for line in self.process.stderr:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                event_type = event.get('type')
                event_data = event.get('data', {})

                # Emit event
                self.emit(event_type, event_data)

            except json.JSONDecodeError:
                # Not JSON, regular stderr output
                print(f"STDERR: {line}", flush=True)

    def wait(self):
        """Wait for scan to complete"""
        if self.process:
            return self.process.wait()
        return None


# Example 1: Simple terminal progress bar
def terminal_example():
    """Simple progress bar in terminal"""
    scanner = DarkScanProgress()

    scanner.on('scan_start', lambda data: print(f"\nStarting scan: {data['path']}"))
    scanner.on('scan_start', lambda data: print(f"Total files: {data['total_files']}\n"))

    def show_progress(data):
        progress = data.get('progress', {})
        percentage = progress.get('percentage', 0)

        # Create progress bar
        bar_width = 50
        filled = int(percentage / 100 * bar_width)
        bar = '█' * filled + '░' * (bar_width - filled)

        scanned = progress.get('scanned', 0)
        total = progress.get('total', 0)
        threats = progress.get('threats', 0)

        print(f"\r[{bar}] {percentage:.1f}% ({scanned}/{total}) Threats: {threats}", end='', flush=True)

        if data.get('infected'):
            print(f"\n⚠️  THREAT: {data['file']}")
            for threat in data.get('threats', []):
                print(f"   - {threat['name']}: {threat['description']}")

    scanner.on('file_scanned', show_progress)

    scanner.on('scan_complete', lambda data: print(f"\n\n✓ Scan complete!"))
    scanner.on('scan_complete', lambda data: print(f"  Scanned: {data['total_scanned']} files"))
    scanner.on('scan_complete', lambda data: print(f"  Threats: {data['threats_found']}"))
    scanner.on('scan_complete', lambda data: print(f"  Duration: {data['duration']:.2f}s"))

    # Start scan
    scanner.scan('/path/to/scan', recursive=True, yara=True)
    scanner.wait()


# Example 2: PyQt5 GUI integration
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                  QProgressBar, QLabel, QPushButton, QFileDialog,
                                  QListWidget, QListWidgetItem)
    from PyQt5.QtCore import QThread, pyqtSignal
    from PyQt5.QtGui import QColor

    class ScanThread(QThread):
        """Background thread for scanning"""
        progress_update = pyqtSignal(dict)
        scan_complete = pyqtSignal(dict)
        threat_detected = pyqtSignal(dict)

        def __init__(self, path, options=None):
            super().__init__()
            self.path = path
            self.options = options or {}
            self.scanner = DarkScanProgress()

        def run(self):
            # Connect scanner events to Qt signals
            self.scanner.on('file_scanned', lambda data: self.progress_update.emit(data))
            self.scanner.on('scan_complete', lambda data: self.scan_complete.emit(data))
            self.scanner.on('threat_detected', lambda data: self.threat_detected.emit(data))

            # Start scan
            self.scanner.scan(self.path, **self.options)
            self.scanner.wait()

    class DarkScanGUI(QMainWindow):
        """PyQt5 GUI for darkscan"""

        def __init__(self):
            super().__init__()
            self.init_ui()
            self.scan_thread = None

        def init_ui(self):
            self.setWindowTitle('DarkScan GUI')
            self.setGeometry(100, 100, 800, 600)

            # Central widget
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)

            # Path label
            self.path_label = QLabel('No path selected')
            layout.addWidget(self.path_label)

            # Select button
            select_btn = QPushButton('Select Directory')
            select_btn.clicked.connect(self.select_directory)
            layout.addWidget(select_btn)

            # Scan button
            self.scan_btn = QPushButton('Start Scan')
            self.scan_btn.clicked.connect(self.start_scan)
            layout.addWidget(self.scan_btn)

            # Progress bar
            self.progress_bar = QProgressBar()
            layout.addWidget(self.progress_bar)

            # Status label
            self.status_label = QLabel('Ready')
            layout.addWidget(self.status_label)

            # Threats list
            self.threats_list = QListWidget()
            layout.addWidget(self.threats_list)

        def select_directory(self):
            path = QFileDialog.getExistingDirectory(self, 'Select Directory to Scan')
            if path:
                self.path_label.setText(f'Path: {path}')
                self.selected_path = path

        def start_scan(self):
            if not hasattr(self, 'selected_path'):
                return

            self.scan_btn.setEnabled(False)
            self.threats_list.clear()

            # Start scan thread
            self.scan_thread = ScanThread(self.selected_path, {'recursive': True, 'yara': True})
            self.scan_thread.progress_update.connect(self.on_progress)
            self.scan_thread.threat_detected.connect(self.on_threat)
            self.scan_thread.scan_complete.connect(self.on_complete)
            self.scan_thread.start()

        def on_progress(self, data):
            progress = data.get('progress', {})
            percentage = progress.get('percentage', 0)
            scanned = progress.get('scanned', 0)
            total = progress.get('total', 0)
            threats = progress.get('threats', 0)

            self.progress_bar.setValue(int(percentage))
            self.status_label.setText(f'Scanned: {scanned}/{total} | Threats: {threats}')

        def on_threat(self, data):
            file_path = data['file']
            threats = data['threats']

            for threat in threats:
                item = QListWidgetItem(f"⚠️  {file_path}: {threat['name']}")
                item.setForeground(QColor('red'))
                self.threats_list.addItem(item)

        def on_complete(self, data):
            self.scan_btn.setEnabled(True)
            self.progress_bar.setValue(100)
            self.status_label.setText(
                f"Complete! Scanned: {data['total_scanned']} | Threats: {data['threats_found']}"
            )

    def pyqt_example():
        """Run PyQt5 GUI"""
        app = QApplication([])
        gui = DarkScanGUI()
        gui.show()
        app.exec_()

except ImportError:
    print("PyQt5 not available, skipping PyQt example")


# Example 3: tkinter GUI integration
try:
    import tkinter as tk
    from tkinter import ttk, filedialog
    import queue

    class TkinterGUI:
        """tkinter GUI for darkscan"""

        def __init__(self):
            self.root = tk.Tk()
            self.root.title('DarkScan GUI')
            self.root.geometry('800x600')

            self.scanner = None
            self.update_queue = queue.Queue()

            self.init_ui()

        def init_ui(self):
            # Path selection
            path_frame = tk.Frame(self.root)
            path_frame.pack(pady=10)

            self.path_var = tk.StringVar(value='No path selected')
            tk.Label(path_frame, textvariable=self.path_var).pack(side=tk.LEFT)
            tk.Button(path_frame, text='Select', command=self.select_path).pack(side=tk.LEFT)

            # Scan button
            tk.Button(self.root, text='Start Scan', command=self.start_scan).pack(pady=10)

            # Progress bar
            self.progress_var = tk.DoubleVar()
            ttk.Progressbar(self.root, variable=self.progress_var, maximum=100).pack(fill=tk.X, padx=20)

            # Status
            self.status_var = tk.StringVar(value='Ready')
            tk.Label(self.root, textvariable=self.status_var).pack(pady=10)

            # Threats list
            self.threats_text = tk.Text(self.root, height=20)
            self.threats_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        def select_path(self):
            path = filedialog.askdirectory()
            if path:
                self.path_var.set(f'Path: {path}')
                self.selected_path = path

        def start_scan(self):
            if not hasattr(self, 'selected_path'):
                return

            self.threats_text.delete('1.0', tk.END)

            self.scanner = DarkScanProgress()
            self.scanner.on('file_scanned', lambda data: self.update_queue.put(('progress', data)))
            self.scanner.on('threat_detected', lambda data: self.update_queue.put(('threat', data)))
            self.scanner.on('scan_complete', lambda data: self.update_queue.put(('complete', data)))

            # Start scan in background thread
            threading.Thread(
                target=lambda: self.scanner.scan(self.selected_path, recursive=True),
                daemon=True
            ).start()

            # Start UI update loop
            self.check_queue()

        def check_queue(self):
            """Check for updates from scanner thread"""
            try:
                while True:
                    event_type, data = self.update_queue.get_nowait()

                    if event_type == 'progress':
                        progress = data.get('progress', {})
                        self.progress_var.set(progress.get('percentage', 0))
                        self.status_var.set(
                            f"Scanned: {progress.get('scanned', 0)}/{progress.get('total', 0)} | "
                            f"Threats: {progress.get('threats', 0)}"
                        )

                    elif event_type == 'threat':
                        self.threats_text.insert(tk.END, f"⚠️  {data['file']}\n", 'threat')
                        for threat in data['threats']:
                            self.threats_text.insert(tk.END, f"   - {threat['name']}\n")

                    elif event_type == 'complete':
                        self.status_var.set(
                            f"Complete! Scanned: {data['total_scanned']} | "
                            f"Threats: {data['threats_found']}"
                        )

            except queue.Empty:
                pass

            # Schedule next check
            self.root.after(100, self.check_queue)

        def run(self):
            self.root.mainloop()

    def tkinter_example():
        """Run tkinter GUI"""
        gui = TkinterGUI()
        gui.run()

except ImportError:
    print("tkinter not available, skipping tkinter example")


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'terminal':
        terminal_example()
    elif len(sys.argv) > 1 and sys.argv[1] == 'pyqt':
        pyqt_example()
    elif len(sys.argv) > 1 and sys.argv[1] == 'tkinter':
        tkinter_example()
    else:
        print("Usage:")
        print("  python gui_progress_parsing.py terminal   # Terminal progress bar")
        print("  python gui_progress_parsing.py pyqt       # PyQt5 GUI")
        print("  python gui_progress_parsing.py tkinter    # tkinter GUI")
