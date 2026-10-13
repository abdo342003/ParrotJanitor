#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parrot Janitor
==============

A desktop GUI for Parrot OS covering six jobs that htop / KDE System Monitor
/ bleachbit don't do *together*:

  1. Runaway process killer -- flags processes pinned at high CPU for a
     SUSTAINED period (the "stuck grep for 4h24m" case), explains what each
     process actually is, and kills it with confirmation.
  2. Resource monitor       -- per-core bars, rolling CPU/RAM history, load,
     memory split and CPU/PCH/Wi-Fi/NVMe temperatures from sysfs.
  3. Port exposure checker  -- classify every listener with a real TLS
     handshake or protocol banner, connect-test 36 common ports, and a
     polkit-gated firewall status view (ufw + nft).
  4. Docker lab manager      -- start/stop your pentest containers in bulk.
  5. btrfs snapshot manager  -- create / inspect / delete @ and @home
     snapshots (root actions go through polkit/pkexec, never plain sudo).
  6. Disk usage + cleanup    -- big-file finder, cache sizes, trash emptying.

Requires: PySide6 (Debian package python3-pyside6.qtwidgets), Python 3.9+
Run:      python3 parrotjanitor.py
Test:     python3 parrotjanitor.py --smoke
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal as _signal
import socket
import ssl
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPointF,
    QRectF,
    QSortFilterProxyModel,
    QThread,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QKeySequence, QPainter, QPen, QPolygonF, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

APP_NAME = "Parrot Janitor"
DESKTOP = Path.home() / "Desktop"
SNAP_DIR = Path("/.snapshots")
PKEXEC = "/usr/bin/pkexec"
BTRFS = "/usr/bin/btrfs"
BASH = "/bin/bash"

DEFAULT_CPU_THRESHOLD = 90.0   # % of one core
DEFAULT_SUSTAIN_SECONDS = 60   # must stay hot this long to count as runaway

# Friendly one-liners for common processes. Falls back to the Debian package
# name, then to the binary basename.
KNOWN_PROCS = {
    "grep": "text search - a pathological regex here is the classic runaway",
    "rg": "ripgrep search",
    "find": "file search - bad -exec/-name patterns can hang forever",
    "sort": "sorting - usually blocked on a pipe, rarely the real culprit",
    "sed": "stream editor",
    "awk": "text processing",
    "head": "reads first N lines of a pipe",
    "tail": "reads last N lines of a pipe",
    "tar": "archiving - slow on huge trees",
    "zip": "compressing",
    "unzip": "extracting an archive",
    "md5sum": "hashing - slow on very large files",
    "sha256sum": "hashing - slow on very large files",
    "rsync": "file sync",
    "rclone": "cloud sync (us-sync / bisync)",
    "btrfs": "btrfs filesystem tool",
    "docker": "Docker client",
    "dockerd": "Docker daemon",
    "containerd": "container runtime daemon",
    "runc": "OCI container runtime (per-container)",
    "node": "Node.js process",
    "nodejs": "Node.js process",
    "next-server": "Next.js server (dev or prod)",
    "python": "Python script",
    "python3": "Python script",
    "java": "JVM - read Command for the actual app",
    "chrome": "Chromium/Chrome tab or renderer",
    "chromium": "Chromium tab or renderer",
    "Discord": "Discord desktop app",
    "discord": "Discord desktop app",
    "opencode": "OpenCode agent session",
    "kwin_wayland": "KDE window manager",
    "plasmashell": "KDE Plasma desktop shell",
    "konsole": "KDE terminal",
    "clickhouse-serv": "ClickHouse analytics DB",
    "mysqld": "MySQL/MariaDB server",
    "postgres": "PostgreSQL server",
    "redis-server": "Redis in-memory store",
    "php-fpm": "PHP worker",
    "nginx": "web server",
    "apache2": "web server",
    "defunct": "zombie process - its parent never reaped it",
}

STYLESHEET = """
* { font-family: 'Noto Sans', 'DejaVu Sans', sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #16232b; color: #d8e2e8; }
QTabWidget::pane { border: 1px solid #24363f; top: -1px; background: #16232b; }
QTabBar::tab {
    background: #1d2f39; color: #9fb3bd; padding: 8px 18px;
    border: 1px solid #24363f; border-bottom: none;
    border-top-left-radius: 5px; border-top-right-radius: 5px;
}
QTabBar::tab:selected { background: #16232b; color: #4fd1a5; font-weight: 600; }
QTabBar::tab:hover { color: #cfe6df; }

QTableView, QTreeView, QTextEdit, QLineEdit, QSpinBox, QComboBox {
    background: #101a20; alternate-background-color: #14212a;
    border: 1px solid #24363f; border-radius: 4px; padding: 3px;
    selection-background-color: #1f6f5c; selection-color: #ffffff;
}
QHeaderView::section {
    background: #1d2f39; color: #a9c0cb; padding: 5px 7px;
    border: none; border-right: 1px solid #24363f; border-bottom: 1px solid #24363f;
}
QPushButton {
    background: #233744; color: #d8e2e8; border: 1px solid #2e4655;
    border-radius: 4px; padding: 6px 14px;
}
QPushButton:hover { background: #2b4553; border-color: #3d6072; }
QPushButton:pressed { background: #1a2b35; }
QPushButton:disabled { color: #5d7078; background: #1a272e; border-color: #202f37; }
QPushButton#danger { background: #7d2b2b; border-color: #a03c3c; }
QPushButton#danger:hover { background: #993636; }
QPushButton#accent { background: #1f6f5c; border-color: #2b9a80; font-weight: 600; }
QPushButton#accent:hover { background: #25866f; }

QGroupBox {
    border: 1px solid #24363f; border-radius: 5px;
    margin-top: 12px; padding-top: 14px; font-weight: 600; color: #9fc3b6;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
QLabel#title { font-size: 20px; font-weight: 700; color: #4fd1a5; }
QLabel#hint { color: #8ba3ad; }
QLabel#stat { color: #cfe0e8; font-weight: 600; }
QLabel#bad { color: #ff8080; font-weight: 700; }
QLabel#warn { color: #f2c14e; font-weight: 600; }
QLabel#good { color: #6ee7a8; font-weight: 600; }
QProgressBar { background: #101a20; border: 1px solid #24363f; border-radius: 4px; text-align: center; }
QProgressBar::chunk { background: #1f6f5c; }
QStatusBar { background: #1d2f39; color: #9fb3bd; }
QCheckBox { spacing: 6px; }
QSplitter::handle { background: #24363f; }
"""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sh(cmd, timeout=30, env=None):
    """Run a command, never raising. Returns (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", "%s: %s" % (type(e).__name__, e)


def human_bytes(n):
    """10792257 -> '10.3 MB'"""
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            if unit == "B":
                return "%d B" % n
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def human_kb(kb):
    return human_bytes(kb * 1024) if kb else "0 B"


def human_duration(seconds):
    if seconds is None or seconds < 0:
        return "-"
    s = int(seconds)
    if s < 60:
        return "%ds" % s
    if s < 3600:
        return "%dm %ds" % (s // 60, s % 60)
    return "%dh %dm" % (s // 3600, (s % 3600) // 60)


def exe_of(pid):
    """Resolve /proc/<pid>/exe, or '' if not permitted."""
    try:
        target = os.readlink("/proc/%d/exe" % pid)
        return target.replace(" (deleted)", "")
    except Exception:
        return ""


def describe_process(exe, args, pkg_cache):
    """Human description: curated note > Debian package > binary name."""
    name = os.path.basename((exe or args.split()[0] if args else "").strip()) or "?"
    name = name.strip()
    if name in KNOWN_PROCS:
        return KNOWN_PROCS[name]
    if exe and exe in pkg_cache and pkg_cache[exe]:
        return "package: " + pkg_cache[exe]
    if exe:
        return name
    return name or "-"


# --------------------------------------------------------------------------
# Process sampling
# --------------------------------------------------------------------------

@dataclass
class ProcRow:
    pid: int
    ppid: int
    user: str
    cpu: float
    mem: float
    rss_kb: int
    state: str
    etimes: int
    args: str
    exe: str = ""
    # filled in by the tab:
    sustained: int = 0          # seconds continuously at/above threshold
    verdict: str = ""           # RUNAWAY / HOT / ""

    @property
    def short(self):
        a = self.args or ""
        if len(a) > 220:
            a = a[:220] + " …"
        return a


def sample_processes():
    rc, out, _ = sh(
        ["ps", "-eo", "pid=,ppid=,user=,pcpu=,pmem=,rss=,stat=,etimes=,args="]
    )
    rows = []
    if rc != 0:
        return rows
    for line in out.splitlines():
        parts = line.strip().split(None, 8)
        if not parts:
            continue
        if len(parts) < 9:
            parts = parts + [""] * (9 - len(parts))
        try:
            row = ProcRow(
                pid=int(parts[0]),
                ppid=int(parts[1]),
                user=parts[2],
                cpu=float(parts[3]),
                mem=float(parts[4]),
                rss_kb=int(parts[5]),
                state=parts[6],
                etimes=int(parts[7]),
                args=parts[8].strip(),
            )
        except (ValueError, IndexError):
            continue
        row.exe = exe_of(row.pid)
        rows.append(row)
    return rows


class RunawayTracker:
    """Keeps per-PID 'continuously hot since' timestamps."""

    def __init__(self, threshold=DEFAULT_CPU_THRESHOLD, sustain=DEFAULT_SUSTAIN_SECONDS):
        self.threshold = threshold
        self.sustain = sustain
        self.hot_since = {}      # pid -> monotonic time it first went hot
        self.last_seen = {}      # pid -> monotonic time we last saw it

    def configure(self, threshold, sustain):
        self.threshold = float(threshold)
        self.sustain = int(sustain)
        self.hot_since.clear()

    def update(self, rows):
        now = time.monotonic()
        live = set()
        for r in rows:
            live.add(r.pid)
            self.last_seen[r.pid] = now
            if r.cpu >= self.threshold:
                self.hot_since.setdefault(r.pid, now)
                r.sustained = int(now - self.hot_since[r.pid])
                if r.sustained >= self.sustain:
                    r.verdict = "RUNAWAY"
                else:
                    r.verdict = "HOT"
            else:
                self.hot_since.pop(r.pid, None)
                r.sustained = 0
                r.verdict = ""
        # prune pids that disappeared
        for d in [p for p in self.last_seen if p not in live]:
            self.last_seen.pop(d, None)
            self.hot_since.pop(d, None)


# --------------------------------------------------------------------------
# Generic background worker
# --------------------------------------------------------------------------

class Task(QThread):
    """Run an arbitrary callable off the UI thread."""
    ok = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs

    def run(self):
        try:
            self.ok.emit(self.fn(*self.args, **self.kwargs))
        except Exception as e:
            self.failed.emit("%s: %s" % (type(e).__name__, e))


class ProcessSampler(QThread):
    """Emits a fresh process list every `interval` ms."""
    updated = Signal(list)

    def __init__(self, interval=2000, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        while not self._stop:
            self.updated.emit(sample_processes())
            # sleep in small slices so we can exit promptly
            for _ in range(max(1, self.interval // 100)):
                if self._stop:
                    return
                self.msleep(100)


# --------------------------------------------------------------------------
# Process table model
# --------------------------------------------------------------------------

COLUMNS = [
    "PID", "User", "CPU%", "MEM%", "RSS", "Sustained", "Age", "State",
    "Verdict", "What it is", "Command",
]


class ProcessModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.pkg_cache = {}
        self.threshold = DEFAULT_CPU_THRESHOLD

    # -- Qt model interface ------------------------------------------------
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()

        if role == Qt.BackgroundRole:
            if r.verdict == "RUNAWAY":
                return QColor("#4a1f22")
            if r.verdict == "HOT":
                return QColor("#44371a")
            return None

        if role == Qt.ForegroundRole:
            if c == 8 and r.verdict:
                return QColor("#ff8b8b" if r.verdict == "RUNAWAY" else "#f2c14e")
            if c == 2 and r.cpu >= self._threshold():
                return QColor("#ff9d9d")
            return None

        if role != Qt.DisplayRole:
            return None

        if c == 0:
            return str(r.pid)
        if c == 1:
            return r.user
        if c == 2:
            return "%.1f" % r.cpu
        if c == 3:
            return "%.1f" % r.mem
        if c == 4:
            return human_kb(r.rss_kb)
        if c == 5:
            return human_duration(r.sustained) if r.sustained else "-"
        if c == 6:
            return human_duration(r.etimes)
        if c == 7:
            return r.state
        if c == 8:
            return r.verdict
        if c == 9:
            return describe_process(r.exe, r.args, self.pkg_cache)
        if c == 10:
            return r.short
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return COLUMNS[section]
        return str(section)

    # -- sorting / filtering support --------------------------------------
    def raw(self, row, col):
        if row < 0 or row >= len(self.rows):
            return None
        r = self.rows[row]
        return [
            r.pid, r.user, r.cpu, r.mem, r.rss_kb, r.sustained, r.etimes,
            r.state, r.verdict, describe_process(r.exe, r.args, self.pkg_cache),
            r.args,
        ][col]

    def pid_at(self, row):
        return self.rows[row].pid if 0 <= row < len(self.rows) else None

    def row_for_pid(self, pid):
        for i, r in enumerate(self.rows):
            if r.pid == pid:
                return i
        return -1

    def _threshold(self):
        return self.threshold

    # -- updates -----------------------------------------------------------
    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class ProcProxy(QSortFilterProxyModel):
    search = ""
    runaway_only = False

    def lessThan(self, left, right):
        src = self.sourceModel()
        a = src.raw(left.row(), self.sortColumn())
        b = src.raw(right.row(), self.sortColumn())
        if a is None or b is None:
            return False
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a < b
        return str(a).lower() < str(b).lower()

    def filterAcceptsRow(self, srcRow, parent):
        src = self.sourceModel()
        if self.runaway_only:
            verdict = src.raw(srcRow, 8)
            if verdict != "RUNAWAY":
                return False
        if not self.search:
            return True
        hay = "%s %s %s" % (
            src.raw(srcRow, 9), src.raw(srcRow, 10), src.raw(srcRow, 1)
        )
        return self.search.lower() in hay.lower()


# --------------------------------------------------------------------------
# Tab 1 - Runaway processes
# --------------------------------------------------------------------------

class ProcessesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tracker = RunawayTracker()
        self.model = ProcessModel(self)
        self.proxy = ProcProxy(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortCaseSensitivity(Qt.CaseInsensitive)
        self._frozen = False
        self._tasks = []          # keep refs alive
        self._lookup_running = False
        self._selected_pid = None

        self.sampler = ProcessSampler(2000, self)
        self.sampler.updated.connect(self.on_sample)
        self.sampler.start()

        self._build_ui()
        self._wire()

    # -- UI ---------------------------------------------------------------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        title = QLabel("Runaway process killer")
        title.setObjectName("title")
        root.addWidget(title)
        hint = QLabel(
            "Flags processes pinned at high CPU for a sustained period — the "
            "“stuck grep for 4½ hours” case. Sort any column; double-click a "
            "row for full details."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

        # -- controls --
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by command, package or user…")
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)

        self.only_runaways = QCheckBox("Runaways only")
        bar.addWidget(self.only_runaways)

        bar.addWidget(QLabel("CPU ≥"))
        self.cpu_spin = QSpinBox()
        self.cpu_spin.setRange(10, 100)
        self.cpu_spin.setValue(int(DEFAULT_CPU_THRESHOLD))
        self.cpu_spin.setSuffix(" %")
        bar.addWidget(self.cpu_spin)

        bar.addWidget(QLabel("for ≥"))
        self.sustain_spin = QSpinBox()
        self.sustain_spin.setRange(5, 3600)
        self.sustain_spin.setValue(DEFAULT_SUSTAIN_SECONDS)
        self.sustain_spin.setSuffix(" s")
        bar.addWidget(self.sustain_spin)

        self.freeze_btn = QPushButton("⏸ Freeze")
        self.freeze_btn.setCheckable(True)
        bar.addWidget(self.freeze_btn)

        self.refresh_btn = QPushButton("↻ Refresh")
        bar.addWidget(self.refresh_btn)

        bar.addStretch(1)

        self.kill_btn = QPushButton("✕ Kill")
        self.kill_btn.setObjectName("danger")
        self.kill_btn.setShortcut(QKeySequence("Delete"))
        bar.addWidget(self.kill_btn)
        root.addLayout(bar)

        # -- table --
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setSectionResizeMode(10, QHeaderView.Stretch)
        hh.setSectionResizeMode(9, QHeaderView.ResizeToContents)
        hh.setSortIndicator(2, Qt.DescendingOrder)
        self.table.sortByColumn(2, Qt.DescendingOrder)
        self.table.setMinimumHeight(320)
        root.addWidget(self.table, 1)

        self.splitter = None
        # -- detail pane --
        detail_box = QGroupBox("Selected process")
        dl = QVBoxLayout(detail_box)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(150)
        self.detail.setPlaceholderText("Select a process to see its full command line, "
                                       "binary path and owning package.")
        dl.addWidget(self.detail)
        root.addWidget(detail_box)

        self.summary = QLabel("Sampling…")
        self.summary.setObjectName("stat")
        root.addWidget(self.summary)

    def _wire(self):
        self.search.textChanged.connect(self._apply_filter)
        self.only_runaways.toggled.connect(self._apply_filter)
        self.cpu_spin.valueChanged.connect(self._configure)
        self.sustain_spin.valueChanged.connect(self._configure)
        self.refresh_btn.clicked.connect(lambda: self.on_sample(sample_processes()))
        self.freeze_btn.toggled.connect(self._toggle_freeze)
        self.kill_btn.clicked.connect(self.kill_selected)
        self.table.doubleClicked.connect(self._show_detail)
        self.table.selectionModel().selectionChanged.connect(self._show_detail)

    # -- behaviour ---------------------------------------------------------
    def _configure(self):
        self.tracker.configure(self.cpu_spin.value(), self.sustain_spin.value())
        self.model.threshold = float(self.cpu_spin.value())
        if not self._frozen:
            self.model.layoutChanged.emit()

    def _apply_filter(self, *_):
        self.proxy.search = self.search.text().strip()
        self.proxy.runaway_only = self.only_runaways.isChecked()
        self.proxy.invalidate()

    def _toggle_freeze(self, checked):
        self._frozen = checked
        self.freeze_btn.setText("▶ Resume" if checked else "⏸ Freeze")

    def on_sample(self, rows):
        if self._frozen:
            return
        self.tracker.update(rows)

        # remember selection so it survives a refresh
        sel = self.proxy.mapToSource(self.table.currentIndex()) if self.table.currentIndex().isValid() else QModelIndex()
        keep = self.model.raw(sel.row(), 0) if sel.isValid() else None

        rows.sort(key=lambda r: r.cpu, reverse=True)
        self.model.set_rows(rows)
        self._apply_filter()

        if keep is not None:
            src = self.model.row_for_pid(keep)
            if src >= 0:
                idx = self.proxy.mapFromSource(self.model.index(src, 0))
                if idx.isValid():
                    self.table.setCurrentIndex(idx)

        runaways = [r for r in rows if r.verdict == "RUNAWAY"]
        hot = [r for r in rows if r.verdict == "HOT"]
        total_cpu = sum(r.cpu for r in rows)
        if runaways:
            self.summary.setText(
                "🔴 %d RUNAWAY  ·  %d hot  ·  %d processes  ·  %.0f%% of 12 threads busy"
                % (len(runaways), len(hot), len(rows), total_cpu)
            )
            self.summary.setObjectName("bad")
        elif hot:
            self.summary.setText(
                "⚠ %d hot (not yet sustained)  ·  %d processes  ·  %.0f%% busy"
                % (len(hot), len(rows), total_cpu)
            )
            self.summary.setObjectName("warn")
        else:
            self.summary.setText(
                "✓ No runaways  ·  %d processes  ·  %.0f%% busy"
                % (len(rows), total_cpu)
            )
            self.summary.setObjectName("good")
        self.summary.style().unpolish(self.summary)
        self.summary.style().polish(self.summary)

        self._maybe_lookup_packages(rows)

    def _maybe_lookup_packages(self, rows):
        """Resolve 'dpkg -S' for unknown binaries in the background."""
        if self._lookup_running:
            return
        unknown = set()
        for r in rows:
            if r.exe and r.exe.startswith("/") and r.exe not in self.model.pkg_cache:
                unknown.add(r.exe)
                if len(unknown) >= 25:
                    break
        if not unknown:
            return
        self._lookup_running = True

        def lookup(paths):
            out = {}
            for p in paths:
                rc, so, _ = sh(["dpkg", "-S", p], timeout=6)
                if rc == 0 and so.strip():
                    out[p] = so.split(":", 1)[0].strip()
                else:
                    out[p] = ""      # remember the miss, don't retry forever
            return out

        t = Task(lookup, sorted(unknown))
        t.ok.connect(self._packages_ready)
        t.failed.connect(lambda m: setattr(self, "_lookup_running", False))
        self._tasks.append(t)
        t.start()

    def _packages_ready(self, found):
        self.model.pkg_cache.update(found)
        self._lookup_running = False
        if not self._frozen:
            idx = self.table.currentIndex()
            self.model.layoutChanged.emit()
            if idx.isValid():
                self.table.setCurrentIndex(idx)

    def _show_detail(self, *_):
        idx = self.table.currentIndex()
        if not idx.isValid():
            return
        src = self.proxy.mapToSource(idx)
        if not src.isValid():
            return
        r = self.model.rows[src.row()]
        lines = [
            "PID         %d      PPID %d" % (r.pid, r.ppid),
            "User        %s" % r.user,
            "Binary      %s" % (r.exe or "(unknown — permission denied)"),
            "Package     %s" % (self.model.pkg_cache.get(r.exe, "") or "n/a"),
            "Started     %s ago" % human_duration(r.etimes),
            "CPU / MEM   %.1f%%  /  %.1f%%   RSS %s" % (r.cpu, r.mem, human_kb(r.rss_kb)),
            "Sustained   %s at ≥%.0f%%%s" % (
                human_duration(r.sustained) if r.sustained else "0s",
                self.tracker.threshold,
                "   → " + r.verdict if r.verdict else "",
            ),
            "",
            "What it is  %s" % describe_process(r.exe, r.args, self.model.pkg_cache),
            "",
            "Command:",
            r.args or "(empty)",
        ]
        self.detail.setPlainText("\n".join(lines))

    def selected_pids(self):
        rows = set()
        for idx in self.table.selectionModel().selectedRows():
            src = self.proxy.mapToSource(idx)
            if src.isValid():
                rows.add(src.row())
        # fall back to the current index if nothing is "selected" as a row
        if not rows and self.table.currentIndex().isValid():
            src = self.proxy.mapToSource(self.table.currentIndex())
            if src.isValid():
                rows.add(src.row())
        return [(self.model.rows[r].pid, self.model.rows[r].short) for r in sorted(rows)]

    # -- killing -----------------------------------------------------------
    def kill_selected(self):
        targets = self.selected_pids()
        if not targets:
            QMessageBox.information(self, "Nothing selected",
                                    "Select one or more processes first.")
            return
        mine = [t for t in targets if t[0] != os.getpid()]
        others = [t for t in targets if t[0] == os.getpid()]
        if not mine:
            QMessageBox.warning(self, "Refusing",
                                "You can't kill Parrot Janitor from inside it.")
            return

        body = ["You are about to send SIGTERM to %d process(es):" % len(mine), ""]
        for pid, cmd in mine[:12]:
            body.append("  %-8d %s" % (pid, cmd[:110]))
        if len(mine) > 12:
            body.append("  … and %d more" % (len(mine) - 12))
        if others:
            body.append("")
            body.append("(Parrot Janitor itself was excluded.)")
        body += ["", "The parent shell usually exits too. Unsaved work in a GUI "
                     "app will be lost."]

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Kill process" if len(mine) == 1 else "Kill %d processes" % len(mine))
        box.setText("Send SIGTERM?")
        box.setDetailedText("\n".join(body))
        box.setInformativeText("\n".join(body[:6]))
        kill_btn = box.addButton("Kill (SIGTERM)", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not kill_btn:
            return

        results = []
        for pid, cmd in mine:
            ok, err = kill_pid(pid, _signal.SIGTERM)
            results.append((pid, cmd, ok, err))
        self._report_kill(results)

    def _report_kill(self, results):
        done = [r for r in results if r[2]]
        failed = [r for r in results if not r[2]]
        if not done:
            msg = "Nothing was killed."
        else:
            msg = "Sent SIGTERM to %d process(es).\n" % len(done)
        if failed:
            msg += "\nFailed:\n"
            needs_root = False
            for pid, cmd, _, err in failed:
                msg += "  %d: %s\n" % (pid, err)
                if "denied" in err:
                    needs_root = True
            if needs_root:
                msg += ("\nThose processes are owned by another user — "
                        "use the button below to escalate via polkit.")
        if failed and any("denied" in r[3] for r in failed):
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Some kills need root")
            box.setText(msg)
            box.setInformativeText("Escalate with pkexec? A polkit password "
                                   "prompt will appear.")
            root_btn = box.addButton("Retry with pkexec", QMessageBox.AcceptRole)
            box.addButton("Close", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() == root_btn:
                self._kill_as_root(failed)
        else:
            QMessageBox.information(self, "Done", msg)
        self.on_sample(sample_processes())

    def _kill_as_root(self, failed):
        def do():
            outputs = []
            for pid, cmd, _, _ in failed:
                rc, so, se = sh([PKEXEC, "/usr/bin/kill", "-TERM", str(pid)], timeout=60)
                outputs.append((pid, rc, (so + se).strip()))
            return outputs

        t = Task(do)
        t.ok.connect(self._root_kill_done)
        t.failed.connect(lambda m: QMessageBox.warning(self, "Error", m))
        self._tasks.append(t)
        self._start_busy("Waiting for polkit authentication…")
        t.start()

    def _root_kill_done(self, outputs):
        self._stop_busy()
        ok = [o for o in outputs if o[1] == 0]
        bad = [o for o in outputs if o[1] != 0]
        msg = "pkexec killed %d process(es)." % len(ok)
        for pid, rc, text in bad:
            msg += "\n  pid %d failed (rc=%d): %s" % (pid, rc, text or "not authorized")
        QMessageBox.information(self, "pkexec", msg)
        self.on_sample(sample_processes())

    def _start_busy(self, text):
        self.setEnabled(False)
        self.summary.setText(text)
        self.summary.setObjectName("warn")

    def _stop_busy(self):
        self.setEnabled(True)

    def shutdown(self):
        self.sampler.stop()
        self.sampler.wait(3000)


# --------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------

def docker_ps():
    rc, out, err = sh([
        "docker", "ps", "-a",
        "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
    ])
    if rc != 0:
        raise RuntimeError(err.strip() or "docker ps failed")
    items = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        items.append({
            "id": p[0], "name": p[1], "image": p[2], "status": p[3],
            "ports": p[4] if len(p) > 4 else "",
        })
    return items


def docker_stats():
    rc, out, err = sh([
        "docker", "stats", "--no-stream",
        "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
    ])
    stats = {}
    if rc != 0:
        return stats
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        try:
            cpu = float(p[1].replace("%", "").strip() or 0)
        except ValueError:
            cpu = 0.0
        stats[p[0]] = {"cpu": cpu, "mem": p[2].strip(), "mempct": p[3].strip()}
    return stats


class DockerModel(QAbstractTableModel):
    COLS = ["Name", "Image", "Status", "CPU%", "Memory", "Ports"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()
        if role == Qt.BackgroundRole:
            if r["state"] == "running":
                return QColor("#173a2e") if index.row() % 2 else QColor("#143328")
            return QColor("#332020") if index.row() % 2 else QColor("#2b1c1c")
        if role != Qt.DisplayRole:
            return None
        return [
            r["name"], r["image"], r["status"],
            ("%.1f" % r["cpu"]) if r["cpu"] else "-",
            r["mem"] or "-", r["ports"],
        ][c]

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLS[section]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class DockerProxy(QSortFilterProxyModel):
    def lessThan(self, left, right):
        src = self.sourceModel()
        a = src.rows[left.row()]
        b = src.rows[right.row()]
        col = self.sortColumn()
        keys = ["name", "image", "status", "cpu", "mem", "ports"]
        av, bv = a[keys[col]], b[keys[col]]
        if isinstance(av, (int, float)) and isinstance(bv, (int, float)):
            return av < bv
        return str(av).lower() < str(bv).lower()


class DockerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.model = DockerModel(self)
        self.proxy = DockerProxy(self)
        self.proxy.setSourceModel(self.model)
        self._tasks = []
        self._busy = False
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        t = QLabel("Docker lab manager")
        t.setObjectName("title")
        root.addWidget(t)
        h = QLabel("You are in the <b>docker</b> group, so no sudo/polkit is needed "
                   "here. Select rows for bulk start/stop.")
        h.setObjectName("hint")
        h.setWordWrap(True)
        root.addWidget(h)

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("↻ Refresh")
        bar.addWidget(self.refresh_btn)
        self.auto_box = QCheckBox("Auto-refresh 5s")
        self.auto_box.setChecked(True)
        bar.addWidget(self.auto_box)
        bar.addStretch(1)
        b_start = QPushButton("▶ Start selected")
        b_stop = QPushButton("■ Stop selected")
        b_restart = QPushButton("⟳ Restart selected")
        b_stopall = QPushButton("■ Stop ALL running")
        b_stopall.setObjectName("danger")
        for b in (b_start, b_stop, b_restart, b_stopall):
            bar.addWidget(b)
        root.addLayout(bar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        self.summary = QLabel("Loading containers…")
        self.summary.setObjectName("stat")
        root.addWidget(self.summary)

        b_start.clicked.connect(lambda: self._act("start"))
        b_stop.clicked.connect(lambda: self._act("stop"))
        b_restart.clicked.connect(lambda: self._act("restart"))
        b_stopall.clicked.connect(self._stop_all)
        self.refresh_btn.clicked.connect(lambda: self.refresh())

        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(lambda: self.refresh(from_timer=True))
        self.timer.start()
        self.refresh()

    # -- data --------------------------------------------------------------
    def refresh(self, from_timer=False):
        if self._busy:
            return
        if from_timer and not self.auto_box.isChecked():
            return
        self._busy = True

        def work():
            items = docker_ps()
            stats = docker_stats()
            for it in items:
                s = stats.get(it["name"], {})
                it["cpu"] = s.get("cpu", 0.0)
                it["mem"] = s.get("mem", "")
                it["state"] = "running" if it["status"].lower().startswith("up") else "exited"
            return items

        t = Task(work)
        t.ok.connect(self._loaded)
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _loaded(self, items):
        self._busy = False
        # preserve selection by container name
        sel = set()
        for idx in self.table.selectionModel().selectedRows():
            src = self.proxy.mapToSource(idx)
            if src.isValid():
                sel.add(self.model.rows[src.row()]["name"])

        items.sort(key=lambda x: (-x["cpu"], x["name"]))
        self.model.set_rows(items)

        for i, it in enumerate(items):
            if it["name"] in sel:
                idx = self.proxy.mapFromSource(self.model.index(i, 0))
                if idx.isValid():
                    self.table.selectRow(idx.row())

        running = [i for i in items if i["state"] == "running"]
        total_cpu = sum(i["cpu"] for i in items)
        self.summary.setText(
            "%d containers · %d running · %d stopped · %.1f%% CPU total"
            % (len(items), len(running), len(items) - len(running), total_cpu)
        )

    def _failed(self, msg):
        self._busy = False
        self.summary.setText("Docker error: " + msg)
        self.summary.setObjectName("bad")

    # -- actions -----------------------------------------------------------
    def _selected_names(self, only_running=False):
        names = []
        for idx in self.table.selectionModel().selectedRows():
            src = self.proxy.mapToSource(idx)
            if not src.isValid():
                continue
            r = self.model.rows[src.row()]
            if only_running and r["state"] != "running":
                continue
            names.append(r["name"])
        return names

    def _act(self, verb):
        names = self._selected_names(only_running=(verb != "start"))
        if not names:
            QMessageBox.information(self, "Nothing selected",
                                    "Select one or more containers first.")
            return
        self._confirm_and_run(verb, names)

    def _stop_all(self):
        names = [r["name"] for r in self.model.rows if r["state"] == "running"]
        if not names:
            QMessageBox.information(self, "Nothing running", "No containers are running.")
            return
        self._confirm_and_run("stop", names, bulk=True)

    def _confirm_and_run(self, verb, names, bulk=False):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Docker %s" % verb)
        box.setText("%s %d container(s)?" % (verb.capitalize(), len(names)))
        detail = "\n".join("  • " + n for n in names[:40])
        if len(names) > 40:
            detail += "\n  … and %d more" % (len(names) - 40)
        box.setDetailedText(detail)
        box.setInformativeText(
            ("ALL RUNNING CONTAINERS WILL BE STOPPED.\n\n" if bulk else "")
            + ", ".join(names[:8]) + ("…" if len(names) > 8 else "")
        )
        go = box.addButton("Confirm", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return
        self._run_verb(verb, names)

    def _run_verb(self, verb, names):
        self._busy = True
        self.summary.setText("Running docker %s …" % verb)

        def work():
            log = []
            for n in names:
                rc, so, se = sh(["docker", verb, n], timeout=90)
                log.append((n, rc, (se or so).strip()[:200]))
            return log

        t = Task(work)
        t.ok.connect(lambda log: self._done(log, verb))
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _done(self, log, verb):
        self._busy = False
        bad = [x for x in log if x[1] != 0]
        if bad:
            msg = "%d failed during %s:\n" % (len(bad), verb)
            for n, rc, text in bad[:10]:
                msg += "  %s (rc=%d): %s\n" % (n, rc, text)
            QMessageBox.warning(self, "Docker", msg)
        else:
            self.summary.setText("%s: %d container(s) OK" % (verb, len(log)))
        self.refresh()


# --------------------------------------------------------------------------
# btrfs snapshots (root via polkit)
# --------------------------------------------------------------------------

SNAP_SCRIPT = r'''
echo "@@@SUB@@@";   btrfs subvolume show /        2>&1
echo "@@@SUB@@@";   btrfs subvolume show /home    2>&1
echo "@@@SNAP@@@";  if [ -d /.snapshots ]; then
                       for d in /.snapshots/*; do
                         [ -e "$d" ] || continue
                         echo "@@@ITEM@@@"
                         btrfs subvolume show "$d" 2>&1
                       done
                     fi
echo "@@@DF@@@";    df -h --output=avail,used,pcent / 2>&1
echo "@@@END@@@"
'''


def pkexec_bash(script, timeout=90):
    """Run a script as root through polkit. Returns (rc, stdout, stderr)."""
    return sh([PKEXEC, BASH, "-c", script], timeout=timeout)


def _parse_subvolume_show(text):
    """Parse `btrfs subvolume show` output into a dict."""
    out = {}
    lines = text.splitlines()
    if lines:
        out["path"] = lines[0].strip()
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower().replace(" ", "_")] = v.strip()
    return out


def fetch_snapshots():
    rc, out, err = pkexec_bash(SNAP_SCRIPT)
    if rc != 0:
        msg = (err or out).strip()
        if rc in (126, 127) or "not authorized" in msg.lower():
            raise PermissionError(
                "Authentication was dismissed or not granted (rc=%d)." % rc
            )
        raise RuntimeError(msg or "pkexec failed (rc=%d)" % rc)

    sections = {"SUB": [], "SNAP": [], "DF": ""}
    current = None
    buf = []
    for line in out.splitlines():
        if line.startswith("@@@") and line.endswith("@@@"):
            key = line.strip("@")
            if key == "END":
                break
            if key in ("SUB", "SNAP", "DF"):
                if current:
                    sections[current].append("\n".join(buf))
                current = key if key in ("SUB", "SNAP") else None
                buf = []
                if key == "DF":
                    sections["DF"] = ""
                continue
            if key == "ITEM":
                sections["SNAP"].append("\n".join(buf))
                buf = []
                current = "SNAP"
                continue
        if current:
            buf.append(line)
        elif current is None and sections.get("DF") is not None:
            sections["DF"] += line + "\n"
    if current and buf:
        sections[current].append("\n".join(buf))

    subs = [_parse_subvolume_show(t) for t in sections["SUB"] if t.strip()]
    snaps = [_parse_subvolume_show(t) for t in sections["SNAP"] if t.strip()]
    snaps = [s for s in snaps if s.get("path")]
    return subs, snaps, sections["DF"].strip()


class SnapshotModel(QAbstractTableModel):
    COLS = ["Name", "Created", "Flags", "Subvol ID", "Parent", "Path"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()
        if role == Qt.BackgroundRole:
            return QColor("#143328") if index.row() % 2 else QColor("#173a2e")
        if role == Qt.ForegroundRole and c == 2:
            return QColor("#6ee7a8") if "readonly" in r.get("flags", "") else QColor("#f2c14e")
        if role != Qt.DisplayRole:
            return None
        return [
            r.get("name", "?"),
            r.get("creation_time", "-"),
            r.get("flags", "-") or "(read-write)",
            r.get("subvolume_id", "-"),
            r.get("parent_uuid", "-")[:13],
            r.get("path", "-"),
        ][c]

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLS[section]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class SnapshotProxy(QSortFilterProxyModel):
    KEYS = ["name", "creation_time", "flags", "subvolume_id", "parent_uuid", "path"]

    def lessThan(self, left, right):
        src = self.sourceModel()
        a = src.rows[left.row()]
        b = src.rows[right.row()]
        col = self.sortColumn()
        av = a.get(self.KEYS[col], "")
        bv = b.get(self.KEYS[col], "")
        if col == 3:
            try:
                return int(av) < int(bv)
            except (TypeError, ValueError):
                return False
        return str(av).lower() < str(bv).lower()


class SnapshotsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.model = SnapshotModel(self)
        self.proxy = SnapshotProxy(self)
        self.proxy.setSourceModel(self.model)
        self._tasks = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        t = QLabel("btrfs snapshot manager")
        t.setObjectName("title")
        root.addWidget(t)
        h = QLabel(
            "Snapshots of <b>@</b> (root) and <b>@home</b>, stored in "
            "<code>/.snapshots/</code>. They are copy-on-write, so they cost "
            "almost nothing until you change data. Every action here needs "
            "root, so a <b>polkit password prompt</b> will appear."
        )
        h.setObjectName("hint")
        h.setWordWrap(True)
        root.addWidget(h)

        info = QGridLayout()
        info.addWidget(QLabel("Snapshots dir"), 0, 0)
        self.lbl_dir = QLabel(str(SNAP_DIR))
        self.lbl_dir.setObjectName("stat")
        info.addWidget(self.lbl_dir, 0, 1)
        info.addWidget(QLabel("Free space on /"), 1, 0)
        self.lbl_free = QLabel("—")
        self.lbl_free.setObjectName("stat")
        info.addWidget(self.lbl_free, 1, 1)
        info.setColumnStretch(2, 1)
        root.addLayout(info)

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("🔐 Authenticate & refresh")
        self.refresh_btn.setObjectName("accent")
        bar.addWidget(self.refresh_btn)
        bar.addStretch(1)
        self.snap_root_btn = QPushButton("＋ Snapshot /")
        self.snap_home_btn = QPushButton("＋ Snapshot /home")
        self.snap_both_btn = QPushButton("＋ Snapshot both")
        self.snap_both_btn.setObjectName("accent")
        self.del_btn = QPushButton("✕ Delete selected")
        self.del_btn.setObjectName("danger")
        for b in (self.snap_root_btn, self.snap_home_btn, self.snap_both_btn, self.del_btn):
            bar.addWidget(b)
        root.addLayout(bar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        self.protected = QLabel("Protected subvolumes: authenticate to list them.")
        self.protected.setObjectName("hint")
        self.protected.setWordWrap(True)
        root.addWidget(self.protected)

        self.summary = QLabel("Not yet authenticated.")
        self.summary.setObjectName("stat")
        root.addWidget(self.summary)

        self.refresh_btn.clicked.connect(self.refresh)
        self.snap_root_btn.clicked.connect(lambda: self.create(True, False))
        self.snap_home_btn.clicked.connect(lambda: self.create(False, True))
        self.snap_both_btn.clicked.connect(lambda: self.create(True, True))
        self.del_btn.clicked.connect(self.delete_selected)

    # -- actions -----------------------------------------------------------
    def refresh(self):
        self._set_busy("Authenticating…")
        t = Task(fetch_snapshots)
        t.ok.connect(self._loaded)
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _loaded(self, payload):
        subs, snaps, df = payload
        self._set_busy(None)
        snaps.sort(key=lambda s: s.get("creation_time", ""), reverse=True)
        self.model.set_rows(snaps)

        if df:
            parts = [p.strip() for p in df.splitlines()[-1].split()]
            if len(parts) >= 3:
                self.lbl_free.setText("%s free (%s used, %s)" % (parts[0], parts[1], parts[2]))

        ro = sum(1 for s in snaps if "readonly" in s.get("flags", ""))
        self.summary.setText(
            "%d snapshot(s) · %d read-only · last %s"
            % (len(snaps), ro, snaps[0].get("creation_time", "?") if snaps else "—")
        )
        desc = []
        for s in subs:
            name = s.get("name", "?")
            flags = s.get("flags", "-") or "read-write"
            desc.append("%s  [%s]  id=%s" % (name, flags, s.get("subvolume_id", "?")))
        self.protected.setText("Protected subvolumes:\n" + ("\n".join(desc) if desc else "—"))

    def _failed(self, msg):
        self._set_busy(None)
        self.summary.setText(msg)
        self.summary.setObjectName("bad")
        self.summary.style().unpolish(self.summary)
        self.summary.style().polish(self.summary)

    def _set_busy(self, text):
        self.setEnabled(text is None)
        if text:
            self.summary.setText(text)
            self.summary.setObjectName("warn")
            self.summary.style().unpolish(self.summary)
            self.summary.style().polish(self.summary)

    def create(self, do_root, do_home):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        parts = ["set -e", "mkdir -p /.snapshots"]
        names = []
        if do_root:
            n = "parrot-root-%s" % stamp
            names.append(n)
            parts.append("btrfs subvolume snapshot -r / /.snapshots/%s" % n)
        if do_home:
            n = "parrot-home-%s" % stamp
            names.append(n)
            parts.append("btrfs subvolume snapshot -r /home /.snapshots/%s" % n)
        script = " && ".join(parts)

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle("Create snapshot")
        box.setText("Create read-only snapshot(s)?")
        box.setInformativeText(
            "Will create:\n" + "\n".join("  /.snapshots/" + n for n in names)
            + "\n\nCopy-on-write: near-zero disk cost."
        )
        go = box.addButton("Create", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return

        self._set_busy("Authenticating…")

        def work():
            return pkexec_bash(script)

        t = Task(work)
        t.ok.connect(lambda res: self._created(res, names))
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _created(self, result, names):
        rc, out, err = result
        self._set_busy(None)
        if rc != 0:
            QMessageBox.warning(
                self, "Snapshot failed",
                "rc=%d\n%s" % (rc, (err or out).strip() or "not authorized"),
            )
        else:
            QMessageBox.information(
                self, "Snapshot created",
                "Created:\n" + "\n".join("  /.snapshots/" + n for n in names),
            )
        self.refresh()

    def delete_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Nothing selected",
                                    "Select a snapshot to delete.")
            return
        names = []
        for r in rows:
            src = self.proxy.mapToSource(r)
            if src.isValid():
                names.append(self.model.rows[src.row()].get("path", ""))
        names = [n for n in names if n]

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Delete snapshot")
        box.setText("Permanently delete %d snapshot(s)?" % len(names))
        box.setDetailedText("\n".join(names))
        box.setInformativeText(
            "This frees space but the snapshot can no longer be rolled back to.\n\n"
            + "\n".join(names[:6])
        )
        go = box.addButton("Delete", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return

        self._set_busy("Authenticating…")
        script = "set -e; " + "; ".join(
            "btrfs subvolume delete %s" % shq(n) for n in names
        )

        def work():
            return pkexec_bash(script)

        t = Task(work)
        t.ok.connect(lambda res: self._deleted(res, names))
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _deleted(self, result, names):
        rc, out, err = result
        self._set_busy(None)
        if rc != 0:
            QMessageBox.warning(self, "Delete failed",
                                "rc=%d\n%s" % (rc, (err or out).strip()))
        else:
            QMessageBox.information(self, "Deleted",
                                    "Removed %d snapshot(s)." % len(names))
        self.refresh()


def shq(s):
    """Minimal POSIX single-quote escaping."""
    return "'" + str(s).replace("'", "'\\''") + "'"


# --------------------------------------------------------------------------
# Disk usage + cleanup
# --------------------------------------------------------------------------

DU_TARGETS = [
    ("Trash", str(Path.home() / ".local/share/Trash")),
    ("User cache", str(Path.home() / ".cache")),
    ("pip cache", str(Path.home() / ".cache/pip")),
    ("Desktop", str(DESKTOP)),
    ("Home", str(Path.home())),
]


def du_bytes(path):
    rc, out, _ = sh(["du", "-sb", path], timeout=180)
    if rc != 0:
        return 0
    first = out.split("\n", 1)[0].strip()
    try:
        return int(first.split()[0])
    except (ValueError, IndexError):
        return 0


def scan_big_files(root, limit=50):
    rc, out, _ = sh(
        ["find", str(root), "-xdev", "-type", "f",
         "-printf", "%s\t%T@\t%p\n"],
        timeout=300,
    )
    if rc != 0:
        return []
    entries = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 3:
            continue
        try:
            entries.append((int(p[0]), p[1], p[2]))
        except ValueError:
            continue
    entries.sort(key=lambda e: e[0], reverse=True)
    return entries[:limit]


def cache_subdirs():
    base = Path.home() / ".cache"
    out = []
    if not base.is_dir():
        return out
    for child in sorted(base.iterdir()):
        try:
            if child.is_dir():
                out.append((child.name, du_bytes(str(child))))
            elif child.is_file():
                out.append((child.name, child.stat().st_size))
        except OSError:
            continue
    out.sort(key=lambda x: x[1], reverse=True)
    return out


class DiskModel(QAbstractTableModel):
    COLS = ["Size", "Modified", "Path"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.BackgroundRole):
            return None
        size, mtime, path = self.rows[index.row()]
        if role == Qt.BackgroundRole:
            return QColor("#143328") if index.row() % 2 else QColor("#173a2e")
        c = index.column()
        if c == 0:
            return human_bytes(size)
        if c == 1:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(mtime)))
        return path

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLS[section]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class DiskProxy(QSortFilterProxyModel):
    def lessThan(self, left, right):
        src = self.sourceModel()
        a = src.rows[left.row()]
        b = src.rows[right.row()]
        col = self.sortColumn()
        if col == 0:
            return a[0] < b[0]
        if col == 1:
            try:
                return float(a[1]) < float(b[1])
            except (TypeError, ValueError):
                return False
        return str(a[2]).lower() < str(b[2]).lower()


class DiskTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.model = DiskModel(self)
        self.proxy = DiskProxy(self)
        self.proxy.setSourceModel(self.model)
        self._tasks = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        t = QLabel("Disk usage + cleanup")
        t.setObjectName("title")
        root.addWidget(t)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        self.sizes_box = QGroupBox("Where the space is")
        gl = QGridLayout(self.sizes_box)
        self.size_labels = {}
        for i, (label, path) in enumerate(DU_TARGETS):
            gl.addWidget(QLabel(label), i, 0)
            lbl = QLabel("—")
            lbl.setObjectName("stat")
            gl.addWidget(lbl, i, 1)
            self.size_labels[label] = lbl
        gl.setColumnStretch(2, 1)
        root.addWidget(self.sizes_box)

        bar = QHBoxLayout()
        b_scan = QPushButton("↻ Scan for big files")
        b_scan.setObjectName("accent")
        bar.addWidget(b_scan)
        b_open = QPushButton("Open containing folder")
        bar.addWidget(b_open)
        bar.addStretch(1)

        b_trash = QPushButton("Empty trash")
        b_trash.setObjectName("danger")
        bar.addWidget(b_trash)
        b_pip = QPushButton("Purge pip cache")
        bar.addWidget(b_pip)
        b_cache = QPushButton("Delete selected cache entry")
        b_cache.setObjectName("danger")
        bar.addWidget(b_cache)
        root.addLayout(bar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        self.summary = QLabel("Click “Scan for big files” (walks your home dir, ~30 s).")
        self.summary.setObjectName("hint")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        b_scan.clicked.connect(self.scan)
        b_open.clicked.connect(self.open_selected)
        b_trash.clicked.connect(self.empty_trash)
        b_pip.clicked.connect(self.purge_pip)
        b_cache.clicked.connect(self.delete_cache)

    # -- actions -----------------------------------------------------------
    def refresh_sizes(self):
        self._run(self._size_work, self._sizes_done, "Measuring…")

    def _size_work(self):
        return {label: du_bytes(path) for label, path in DU_TARGETS}

    def _sizes_done(self, result):
        for label, val in result.items():
            if label in self.size_labels:
                self.size_labels[label].setText(human_bytes(val))

    def scan(self):
        self.progress.setVisible(True)
        self.summary.setText("Scanning /home for the biggest files…")
        self._run(lambda: scan_big_files(Path.home(), 60), self._scan_done,
                  "Scanning…")

    def _scan_done(self, rows):
        self.progress.setVisible(False)
        self.model.set_rows(rows)
        total = sum(r[0] for r in rows)
        self.summary.setText(
            "Top %d files in %s — together %s. Sorting by size; click a column "
            "header to re-sort." % (len(rows), Path.home(), human_bytes(total))
        )
        self.refresh_sizes()

    def _scan_failed(self, msg):
        self.progress.setVisible(False)
        self.summary.setText("Scan failed: " + msg)

    def _selected_path(self):
        """Resolve the current selection through the proxy to a real path."""
        idx = self.table.currentIndex()
        if not idx.isValid():
            return None
        src = self.proxy.mapToSource(idx)
        if not src.isValid():
            return None
        return self.model.rows[src.row()][2]

    def open_selected(self):
        path = self._selected_path()
        if not path:
            QMessageBox.information(self, "Nothing selected", "Select a file first.")
            return
        folder = str(Path(path).parent)
        sh(["xdg-open", folder], timeout=15)

    def empty_trash(self):
        size = du_bytes(str(Path.home() / ".local/share/Trash"))
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Empty trash")
        box.setText("Permanently delete everything in the trash?")
        box.setInformativeText(
            "This frees %s and is NOT recoverable.\n\n"
            "Careful: earlier cleanup work from this session is still in the "
            "trash (temp/Hajar, temp/Reda, the old gocryptfs vault, 7 photos)." % human_bytes(size)
        )
        go = box.addButton("Empty trash", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return
        self._run(lambda: sh(["gio", "trash", "--empty"], timeout=120),
                  lambda r: self._after("Trash emptied", r),
                  "Emptying trash…", show_err=True)

    def purge_pip(self):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Purge pip cache")
        box.setText("Delete the pip download cache?")
        box.setInformativeText("Safe — pip just re-downloads packages next time.")
        go = box.addButton("Purge", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return
        self._run(lambda: sh([sys.executable, "-m", "pip", "cache", "purge"], timeout=180),
                  lambda r: self._after("pip cache purged", r),
                  "Purging…", show_err=True)

    def delete_cache(self):
        path = self._selected_path()
        if not path:
            QMessageBox.information(self, "Nothing selected", "Select a file first.")
            return
        # only allow deleting things that live inside ~/.cache
        cache_root = str((Path.home() / ".cache").resolve())
        try:
            rel = os.path.relpath(path, cache_root)
        except ValueError:
            rel = ".."
        if rel.startswith("..") or rel in (".", os.curdir):
            QMessageBox.warning(
                self, "Refused",
                "Only entries inside ~/.cache can be deleted from here.\n\n" + path
            )
            return
        target = rel.split(os.sep)[0]
        if not target or target == os.sep:
            return
        size = du_bytes(str(Path.home() / ".cache" / target))
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Delete cache entry")
        box.setText("Delete ~/.cache/%s (%s)?" % (target, human_bytes(size)))
        box.setInformativeText("Apps will rebuild it on next use.")
        go = box.addButton("Delete", QMessageBox.AcceptRole)
        box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(box.buttons()[-1])
        box.exec()
        if box.clickedButton() is not go:
            return
        full = str(Path.home() / ".cache" / target)
        self._run(lambda: sh(["rm", "-rf", "--", full], timeout=180),
                  lambda r: self._after("Deleted ~/.cache/" + target, r),
                  "Deleting…", show_err=True)

    # -- plumbing ----------------------------------------------------------
    def _run(self, fn, on_ok, busy_text, on_err=None, show_err=False):
        self.summary.setText(busy_text)

        def wrapped():
            return fn()

        t = Task(wrapped)
        t.ok.connect(on_ok)
        if on_err:
            t.failed.connect(on_err)
        else:
            t.failed.connect(lambda m: self.summary.setText("Error: " + m))
        self._tasks.append(t)
        t.start()

    def _after(self, label, result):
        rc, out, err = result if isinstance(result, tuple) and len(result) == 3 else (0, "", "")
        if rc not in (0, None):
            self.summary.setText("%s — rc=%d %s" % (label, rc, (err or out).strip()[:160]))
        else:
            self.summary.setText(label + " ✓")
        self.refresh_sizes()


# --------------------------------------------------------------------------
# Resources — per-core CPU, history, RAM, load, temperature
# --------------------------------------------------------------------------

_THERMAL_LABELS = {
    "x86_pkg_temp": "CPU package",
    "coretemp": "CPU cores",
    "acpitz": "ACPI thermal zone",
    "pch_cometlake": "Platform hub",
    "pch_cannonlake": "Platform hub",
    "iwlwifi_1": "Wi-Fi radio",
    "iwlwifi_0": "Wi-Fi radio",
    "nvme": "NVMe SSD",
    "BAT1": "Battery",
    "AMDSM": "AMD SM",
}

# Segment colours for the memory bar (they tile exactly to MemTotal).
_MEM_COLOURS = {"used": "#4fd1a5", "cache": "#1f6f5c", "free": "#1d2f39"}
_SWAP_COLOURS = {"used": "#f2c14e", "free": "#1d2f39"}


def read_cpu_times():
    """jiffies from /proc/stat -> (total, idle, [(total, idle), …]) per core."""
    cores = []
    total = idle = 0
    try:
        with open("/proc/stat") as fh:
            for line in fh:
                parts = line.split()
                if not parts:
                    continue
                name = parts[0]
                if not name.startswith("cpu"):
                    break  # 'intr' — done with the cpu lines
                vals = [int(x) for x in parts[1:11]]
                jiffies = sum(vals)
                # idle + iowait both count as idle
                still = vals[3] + (vals[4] if len(vals) > 4 else 0)
                if name == "cpu":
                    total, idle = jiffies, still
                else:
                    cores.append((jiffies, still))
    except (OSError, ValueError, IndexError):
        return 0, 0, []
    return total, idle, cores


def _delta_pct(prev, cur):
    """prev/cur are (total_jiffies, idle_jiffies) -> busy percentage."""
    dt = cur[0] - prev[0]
    di = cur[1] - prev[1]
    if dt <= 0:
        return 0.0
    return max(0.0, min(100.0, (1.0 - di / dt) * 100.0))


def read_meminfo():
    want = {
        "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
        "SwapTotal", "SwapFree", "Shmem", "SReclaimable",
    }
    out = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, sep, rest = line.partition(":")
                if not sep or key not in want:
                    continue
                try:
                    out[key] = int(rest.split()[0]) * 1024   # kB -> bytes
                except (ValueError, IndexError):
                    pass
    except OSError:
        pass
    return out


def read_loadavg():
    try:
        with open("/proc/loadavg") as fh:
            p = fh.read().split()
        return float(p[0]), float(p[1]), float(p[2]), p[3]
    except (OSError, ValueError, IndexError):
        return 0.0, 0.0, 0.0, "-"


def read_temps():
    """[(label, °C), …] from /sys/class/thermal, skipping implausible values."""
    base = "/sys/class/thermal"
    try:
        zones = sorted(
            (z for z in os.listdir(base) if z.startswith("thermal_zone")),
            key=lambda s: int(re.sub(r"\D", "", s) or 0),
        )
    except OSError:
        zones = []
    out = []
    for zone in zones:
        try:
            raw = int(open(os.path.join(base, zone, "temp")).read().strip())
            ztype = open(os.path.join(base, zone, "type")).read().strip()
        except (OSError, ValueError):
            continue
        if raw <= 0 or raw > 150000:
            continue
        out.append((_THERMAL_LABELS.get(ztype, ztype), raw / 1000.0))
    return out


def _heat(pct):
    if pct < 50:
        return QColor("#4fd1a5")
    if pct < 80:
        return QColor("#f2c14e")
    return QColor("#ff7a7a")


class ResourceSampler(QThread):
    """Samples /proc every `interval` ms and emits a plain dict."""
    updated = Signal(dict)

    def __init__(self, interval=1000, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        prev_total, prev_idle, prev_cores = read_cpu_times()
        while not self._stop:
            for _ in range(max(1, self.interval // 50)):
                if self._stop:
                    return
                self.msleep(50)
            cur_total, cur_idle, cur_cores = read_cpu_times()
            sample = {
                "cpu": _delta_pct((prev_total, prev_idle), (cur_total, cur_idle)),
                "cores": [
                    _delta_pct(p, c) for p, c in zip(prev_cores, cur_cores)
                ],
                "mem": read_meminfo(),
                "load": read_loadavg(),
                "temps": read_temps(),
            }
            prev_total, prev_idle, prev_cores = cur_total, cur_idle, cur_cores
            self.updated.emit(sample)


class HistoryChart(QWidget):
    """Scrolling 0–100% line chart. QtCharts isn't packaged here, so QPainter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cpu = deque(maxlen=420)
        self.mem = deque(maxlen=420)
        self.setMinimumHeight(190)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def append(self, cpu, mem):
        self.cpu.append(cpu)
        self.mem.append(mem)
        self.update()

    def clear(self):
        self.cpu.clear()
        self.mem.clear()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.fillRect(self.rect(), QColor("#101a20"))

        rect = QRectF(self.rect()).adjusted(8, 8, -8, -30)
        p.fillRect(rect, QColor("#0c151a"))
        p.setPen(QPen(QColor("#24363f"), 1))
        p.drawRect(rect)

        for frac in (0.25, 0.5, 0.75):
            y = rect.top() + rect.height() * frac
            p.setPen(QPen(QColor("#1d2f39"), 1, Qt.DashLine))
            p.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))

        if len(self.cpu) >= 2:
            n = len(self.cpu)
            for values, colour in ((self.cpu, "#f2c14e"), (self.mem, "#4fd1a5")):
                vals = list(values)
                pts = [
                    QPointF(
                        rect.left() + rect.width() * i / (n - 1),
                        rect.bottom() - rect.height() * min(v, 100.0) / 100.0,
                    )
                    for i, v in enumerate(vals)
                ]
                p.setPen(QPen(QColor(colour), 1.8))
                p.drawPolyline(QPolygonF(pts))

        font = p.font()
        font.setPointSize(8)
        p.setFont(font)
        p.setPen(QColor("#8ba3ad"))
        bottom = rect.bottom() + 18
        if self.cpu:
            p.setPen(QColor("#f2c14e"))
            p.drawText(QPointF(rect.left(), bottom), "CPU %.0f%%" % self.cpu[-1])
            p.setPen(QColor("#4fd1a5"))
            p.drawText(QPointF(rect.left() + 78, bottom), "RAM %.0f%%" % self.mem[-1])
        p.setPen(QColor("#8ba3ad"))
        label = "%d samples" % len(self.cpu) if self.cpu else "waiting for samples…"
        p.drawText(
            QRectF(rect.right() - 160, bottom - 12, 160, 14),
            Qt.AlignRight | Qt.AlignVCenter,
            label,
        )


class CoreBars(QWidget):
    """Compact per-thread utilisation bars, `columns` wide."""

    def __init__(self, columns=2, parent=None):
        super().__init__(parent)
        self.columns = columns
        self.values = []
        self.setMinimumHeight(72)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set_values(self, vals):
        self.values = list(vals)
        rows = max(1, (len(self.values) + self.columns - 1) // self.columns)
        self.setMinimumHeight(max(72, rows * 26 + 6))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        if not self.values:
            p.setPen(QColor("#8ba3ad"))
            p.drawText(self.rect(), Qt.AlignCenter, "No CPU data yet")
            return
        n = len(self.values)
        rows = max(1, (n + self.columns - 1) // self.columns)
        cell_h = self.height() / rows
        col_w = self.width() / self.columns
        for i, pct in enumerate(self.values):
            r, c = divmod(i, self.columns)
            x, y = c * col_w, r * cell_h
            bar = QRectF(x + 34, y + cell_h * 0.34, col_w - 78, max(7.0, cell_h * 0.30))
            p.fillRect(bar, QColor("#0c151a"))
            fill = QRectF(bar)
            fill.setWidth(max(0.0, bar.width() * pct / 100.0))
            p.fillRect(fill, _heat(pct))
            p.setPen(QColor("#8ba3ad"))
            p.drawText(
                QRectF(x + 2, y, 28, cell_h),
                Qt.AlignVCenter | Qt.AlignRight,
                "T%d" % i,
            )
            p.setPen(QColor("#d8e2e8"))
            p.drawText(
                QRectF(bar.right() + 6, y, 42, cell_h),
                Qt.AlignVCenter | Qt.AlignLeft,
                "%.0f%%" % pct,
            )


class MemBar(QWidget):
    """Stacked horizontal bar: [(label, bytes, colour), …]."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parts = []
        self.total = 0
        self.setMinimumHeight(24)

    def set_parts(self, parts, total):
        self.parts, self.total = parts, total
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        rect = QRectF(self.rect()).adjusted(0, 4, 0, -4)
        if not self.total:
            p.fillRect(rect, QColor("#101a20"))
            return
        x = rect.left()
        for _label, value, colour in self.parts:
            w = rect.width() * (value / self.total)
            if w <= 0:
                continue
            p.fillRect(QRectF(x, rect.top(), w, rect.height()), colour)
            x += w
        p.setPen(QPen(QColor("#24363f"), 1))
        p.drawRect(rect)


class ResourcesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_summary = "Sampling…"
        self._build_ui()
        self.sampler = ResourceSampler(1000, self)
        self.sampler.updated.connect(self.on_sample)
        self.sampler.start()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        title = QLabel("CPU, RAM & temperature")
        title.setObjectName("title")
        root.addWidget(title)
        hint = QLabel(
            "Per-thread utilisation with heat colouring, a rolling 7-minute "
            "history, and memory broken into in-use / reclaimable cache / free. "
            "Temperatures come from <code>/sys/class/thermal</code>."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

        body = QHBoxLayout()

        # ---- left column: CPU, load, temps -----------------------------
        left = QVBoxLayout()

        cpu_box = QGroupBox("CPU utilisation")
        cpu_lay = QVBoxLayout(cpu_box)
        self.cores = CoreBars(2)
        cpu_lay.addWidget(self.cores)
        self.cpu_total = QLabel("—")
        self.cpu_total.setObjectName("stat")
        cpu_lay.addWidget(self.cpu_total)
        left.addWidget(cpu_box)

        load_box = QGroupBox("Load average")
        load_grid = QGridLayout(load_box)
        self.load_labels = []
        for row, name in enumerate(("1 min", "5 min", "15 min", "Runnable")):
            load_grid.addWidget(QLabel(name), row, 0)
            val = QLabel("—")
            val.setObjectName("stat")
            val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            load_grid.addWidget(val, row, 1)
            self.load_labels.append(val)
        load_grid.setColumnStretch(1, 1)
        left.addWidget(load_box)

        temp_box = QGroupBox("Temperature")
        self.temp_grid = QGridLayout(temp_box)
        self._temp_rows = {}
        rows = read_temps()
        for i, (label, _c) in enumerate(rows):
            self.temp_grid.addWidget(QLabel(label), i, 0)
            val = QLabel("—")
            val.setObjectName("stat")
            val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.temp_grid.addWidget(val, i, 1)
            self._temp_rows[label] = val
        if not rows:
            self.temp_grid.addWidget(QLabel("no thermal zones readable"), 0, 0)
        self.temp_grid.setColumnStretch(1, 1)
        left.addWidget(temp_box)
        left.addStretch(1)

        # ---- right column: history, memory -----------------------------
        right = QVBoxLayout()

        hist_box = QGroupBox("History (last 7 minutes)")
        hist_lay = QVBoxLayout(hist_box)
        self.chart = HistoryChart()
        hist_lay.addWidget(self.chart)
        right.addWidget(hist_box, 1)

        mem_box = QGroupBox("Memory")
        mem_lay = QVBoxLayout(mem_box)
        self.mem_bar = MemBar()
        mem_lay.addWidget(self.mem_bar)
        self.mem_stats = QLabel("—")
        self.mem_stats.setWordWrap(True)
        mem_lay.addWidget(self.mem_stats)
        self.swap_bar = MemBar()
        mem_lay.addWidget(self.swap_bar)
        self.swap_stats = QLabel("—")
        self.swap_stats.setWordWrap(True)
        mem_lay.addWidget(self.swap_stats)
        right.addWidget(mem_box)

        body.addLayout(left, 0)
        body.addLayout(right, 1)
        root.addLayout(body, 1)

        self.summary = QLabel("Sampling…")
        self.summary.setObjectName("stat")
        root.addWidget(self.summary)

    # -- updates ---------------------------------------------------------
    def on_sample(self, s):
        cores = s["cores"]
        self.cores.set_values(cores)
        cpu = s["cpu"]

        hottest = max(cores) if cores else 0.0
        self.cpu_total.setText(
            "%d threads · %.1f%% busy · hottest T%d at %.0f%%"
            % (len(cores), cpu, cores.index(hottest) if cores else 0, hottest)
        )

        load = s["load"]
        self.load_labels[0].setText("%.2f" % load[0])
        self.load_labels[1].setText("%.2f" % load[1])
        self.load_labels[2].setText("%.2f" % load[2])
        self.load_labels[3].setText(str(load[3]))

        for label, celsius in s["temps"]:
            row = self._temp_rows.get(label)
            if row is None:
                continue
            row.setText("%.0f °C" % celsius)
            row.setObjectName(
                "bad" if celsius >= 85 else ("warn" if celsius >= 75 else "stat")
            )
            row.style().unpolish(row)
            row.style().polish(row)

        m = s["mem"]
        total = m.get("MemTotal", 0)
        free = m.get("MemFree", 0)
        avail = m.get("MemAvailable", 0)
        used = max(0, total - avail)          # procps "used"
        cache = max(0, avail - free)          # reclaimable cache/buffers
        if total:
            self.mem_bar.set_parts([
                ("In use", used, _MEM_COLOURS["used"]),
                ("Cache", cache, _MEM_COLOURS["cache"]),
                ("Free", free, _MEM_COLOURS["free"]),
            ], total)
            self.mem_stats.setText(
                "%s in use · %s reclaimable cache · %s free &nbsp;—&nbsp; "
                "%s total, %s available"
                % (human_bytes(used), human_bytes(cache), human_bytes(free),
                   human_bytes(total), human_bytes(avail))
            )

        stotal = m.get("SwapTotal", 0)
        sfree = m.get("SwapFree", 0)
        sused = max(0, stotal - sfree)
        if stotal:
            self.swap_bar.set_parts([
                ("Swap used", sused, _SWAP_COLOURS["used"]),
                ("Swap free", sfree, _SWAP_COLOURS["free"]),
            ], stotal)
            pct = 100.0 * sused / stotal
            self.swap_stats.setText(
                "Swap %s of %s used (%.0f%%)"
                % (human_bytes(sused), human_bytes(stotal), pct)
            )
        else:
            self.swap_stats.setText("No swap configured")

        self.chart.append(cpu, 100.0 * used / total if total else 0.0)
        self._update_summary(s)

    def _update_summary(self, s=None):
        if s is None:
            return
        m = s["mem"]
        total = m.get("MemTotal", 0)
        used = max(0, total - m.get("MemAvailable", 0))
        temps = s["temps"]
        cpu_temp = next((c for l, c in temps if l.startswith("CPU")), None)
        parts = [
            "CPU %.1f%%" % s["cpu"],
            "load %.2f / %.2f / %.2f" % tuple(s["load"][:3]),
            "%s / %s RAM" % (human_bytes(used), human_bytes(total)),
        ]
        if cpu_temp is not None:
            parts.append("CPU %.0f °C" % cpu_temp)
        self._last_summary = " · ".join(parts)
        self.summary.setText(self._last_summary)

    def shutdown(self):
        self.sampler.stop()
        self.sampler.wait(3000)


# --------------------------------------------------------------------------
# Ports — listening sockets, exposure, real TLS/banner probing
# --------------------------------------------------------------------------

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (111, "RPCBind"), (135, "MSRPC"),
    (139, "NetBIOS"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
    (465, "SMTPS"), (587, "Submission"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (2049, "NFS"), (2375, "Docker API"),
    (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
    (6379, "Redis"), (6443, "K8s API"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
    (9090, "Prometheus"), (9200, "Elasticsearch"), (9418, "Git"),
    (9993, "ZeroTier"), (11211, "Memcached"), (11434, "Ollama"),
    (27017, "MongoDB"),
]

# Reachable from more than loopback without TLS == a genuine exposure.
HIGH_RISK_PORTS = {
    21, 23, 79, 80, 110, 111, 119, 135, 139, 143, 389, 445, 512, 513, 514,
    515, 631, 873, 1433, 1521, 2049, 2375, 2376, 3000, 3128, 3306, 3389,
    5432, 5900, 5901, 5985, 5986, 6379, 6443, 8000, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9300, 11211, 11434, 15672, 27017, 27018, 50000,
}

_VERDICTS = ("Secured", "Local", "Open", "Exposed", "Unknown")
_VERDICT_COLOUR = {
    "Secured": QColor("#6ee7a8"),
    "Local": QColor("#7fbfff"),
    "Open": QColor("#f2c14e"),
    "Exposed": QColor("#ff8080"),
    "Unknown": QColor("#9fb3bd"),
    "—": QColor("#9fb3bd"),
}
_VERDICT_BG = {
    "Secured": QColor("#122b23"),
    "Local": QColor("#152534"),
    "Open": QColor("#33290f"),
    "Exposed": QColor("#3a1a1c"),
    "Unknown": QColor("#1b2730"),
    "—": QColor("#14212a"),
}

_SS_NETIDS = {"tcp", "udp", "udplite", "sctp", "dccp", "raw", "unix"}


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def split_addr(addr):
    """'0.0.0.0:22' / '[::]:22' / '192.168.1.5%virbr0:53' -> (host, port)."""
    addr = (addr or "").strip()
    if addr.startswith("["):
        close = addr.find("]")
        if close != -1:
            tail = addr[close + 1:]
            return addr[1:close], _int(tail[1:]) if tail.startswith(":") else 0
    if addr.count(":") == 1:
        host, _, port = addr.partition(":")
        return host, _int(port)
    head, sep, tail = addr.rpartition(":")
    if sep and tail.isdigit():
        return head, _int(tail)
    return addr, 0


def classify_scope(host):
    h = (host or "").split("%")[0]
    if h in ("127.0.0.1", "::1", "localhost"):
        return "Loopback"
    if h in ("0.0.0.0", "::", "*", ""):
        return "All interfaces"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        octets = [int(x) for x in h.split(".")]
        if octets[0] == 127:
            return "Loopback"
        if octets[0] == 10:
            return "LAN"
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return "LAN"
        if octets[0] == 192 and octets[1] == 168:
            return "LAN"
        if octets[0] == 169 and octets[1] == 254:
            return "Link-local"
        if octets[0] >= 224:
            return "Multicast"
        return "Public"
    if h.count(":") >= 2:
        if h.startswith("fe80:"):
            return "Link-local"
        if h.startswith("fc") or h.startswith("fd"):
            return "LAN"
        return "Public"
    return "Other"


_SERVICES_CACHE = None


def service_names():
    """Parse /etc/services once -> ({tcp: {port: name}}, {udp: …})."""
    global _SERVICES_CACHE
    if _SERVICES_CACHE is None:
        tables = {"tcp": {}, "udp": {}}
        try:
            with open("/etc/services") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2 or "/" not in parts[1]:
                        continue
                    port_s, _, proto = parts[1].partition("/")
                    port = _int(port_s)
                    if port and proto in tables:
                        tables[proto].setdefault(port, parts[0])
        except OSError:
            pass
        _SERVICES_CACHE = (tables["tcp"], tables["udp"])
    return _SERVICES_CACHE


def listening_sockets():
    """`ss -H -lntup` -> list of dicts (proto, port, host, addr, scope, …)."""
    rc, out, _err = sh(["ss", "-H", "-lntup"], timeout=25)
    socks = []
    if rc != 0:
        return socks
    tcp_services, udp_services = service_names()
    for line in out.splitlines():
        toks = line.split()
        if not toks:
            continue
        idx = 0
        proto = "tcp"
        if toks[0] in _SS_NETIDS:
            proto = toks[0]
            idx = 1
        if len(toks) < idx + 5:
            continue
        state = toks[idx]
        local = toks[idx + 3]
        rest = " ".join(toks[idx + 5:])
        host, port = split_addr(local)
        if proto == "unix" or ":" not in local:
            continue
        proc, pid = "", ""
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', rest)
        if m:
            proc, pid = m.group(1), m.group(2)
        table = tcp_services if proto == "tcp" else udp_services
        socks.append({
            "proto": proto,
            "state": state,
            "host": host,
            "port": port,
            "addr": local,
            "scope": classify_scope(host),
            "proc": proc,
            "pid": pid,
            "service": table.get(port, ""),
            "probe": None,
            "verdict": "Unknown",
            "detail": "not probed yet",
        })
    return socks


def _probe_candidates(sock):
    host = (sock["host"] or "").split("%")[0]
    if host in ("0.0.0.0", "::", "*", ""):
        return ["127.0.0.1", "::1"]
    return [host]


def probe_listener(sock, timeout=0.6):
    """Banner read + TLS handshake against one listener. Never raises."""
    result = {"connect": False, "tls": False, "banner": "", "error": "",
              "tls_ver": ""}
    if sock["proto"] != "tcp" or not sock["port"]:
        result["error"] = "UDP / no port — not probed"
        return result

    last_err = ""
    for cand in _probe_candidates(sock):
        try:
            with socket.create_connection((cand, sock["port"]), timeout=timeout) as s:
                result["connect"] = True
                s.settimeout(timeout)
                try:
                    data = s.recv(96)
                    result["banner"] = data.decode("latin-1", "replace").strip()[:70]
                except (socket.timeout, OSError):
                    pass
            break
        except OSError as e:
            last_err = str(e)

    if not result["connect"]:
        # genuinely unreachable — that is worth reporting
        result["error"] = last_err or "connection refused"
        return result

    result["error"] = ""   # a TLS handshake timeout just means "no TLS here"
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((cand, sock["port"]), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                result["tls"] = True
                result["tls_ver"] = tls.version() or "TLS"
    except (ssl.SSLError, OSError):
        result["tls"] = False
    return result


def scan_common_ports(timeout=0.4, workers=16):
    """TCP connect test of COMMON_PORTS against 127.0.0.1 -> [(port, desc, bool)]."""
    def check(item):
        port, desc = item
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                return (port, desc, True)
        except OSError:
            return (port, desc, False)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(check, COMMON_PORTS))


def verdict_for(sock, probe):
    """(verdict, detail) — the actual security assessment for one listener."""
    scope = sock["scope"]
    service = sock["service"] or ("port %d" % sock["port"])
    probe = probe or {}

    if probe.get("tls"):
        return "Secured", "TLS handshake succeeded (%s)" % probe.get("tls_ver", "TLS")

    banner = probe.get("banner") or ""
    if banner.startswith("SSH-"):
        return "Secured", "SSH — %s" % banner.split(",")[0][:28]

    if scope == "Loopback":
        return "Secured", "bound to 127.0.0.1 — not reachable off this machine"

    if probe.get("error"):
        return "Unknown", "could not probe: %s" % probe["error"]

    # multicast / link-local only crosses this network segment
    if scope in ("Multicast", "Link-local"):
        if sock["port"] in HIGH_RISK_PORTS:
            return "Exposed", "%s reachable from %s" % (service, scope.lower())
        return "Local", "%s bound to %s — only this network segment" % (
            sock["proto"].upper(), scope.lower())

    if sock["proto"] == "udp":
        if sock["port"] in HIGH_RISK_PORTS:
            return "Exposed", "%s UDP reachable from %s" % (
                service, scope.lower())
        return "Open", "UDP reachable from %s — connectionless, " \
                       "confirm it is intended" % scope.lower()

    if sock["port"] in HIGH_RISK_PORTS:
        return "Exposed", "%s reachable from %s, no TLS detected" % (
            service, scope.lower())

    return "Open", "no TLS detected on %s" % scope.lower()


def firewall_report():
    """One-shot root read of ufw + nft. Read-only; changes nothing."""
    script = (
        "echo '=== ufw status ==='; ufw status verbose 2>&1; "
        "echo; echo '=== nft ruleset (first 120 lines) ==='; "
        "nft list ruleset 2>&1 | head -120; "
        "echo; echo '=== nft counters by table ==='; "
        "nft list ruleset 2>&1 | grep -E '^\\s*(table|chain|policy)' | head -60"
    )
    return pkexec_bash(script, timeout=60)


class ListenerModel(QAbstractTableModel):
    COLS = ["Proto", "Port", "Service", "Local address", "Scope",
            "Process", "Verdict", "Detail"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()
        if role == Qt.BackgroundRole:
            return _VERDICT_BG.get(r["verdict"], QColor("#14212a"))
        if role == Qt.ForegroundRole and c == 6:
            return _VERDICT_COLOUR.get(r["verdict"], QColor("#d8e2e8"))
        if role == Qt.ForegroundRole and c == 5:
            return QColor("#8ba3ad")
        if role != Qt.DisplayRole:
            return None
        return [
            r["proto"].upper(),
            str(r["port"]) if r["port"] else "-",
            r["service"] or "-",
            r["addr"],
            r["scope"],
            (r["proc"] or "-") + (" [%s]" % r["pid"] if r["pid"] else ""),
            r["verdict"],
            r["detail"],
        ][c]

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLS[section]
        return None

    def raw(self, row, col):
        if row < 0 or row >= len(self.rows):
            return None
        r = self.rows[row]
        return [
            r["proto"], r["port"], r["service"], r["addr"], r["scope"],
            r["proc"], r["verdict"], r["detail"],
        ][col]

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class ListenerProxy(QSortFilterProxyModel):
    mode = 0          # 0 all · 1 exposed only · 2 not-secured only · 3 tcp only

    def lessThan(self, left, right):
        src = self.sourceModel()
        a = src.raw(left.row(), self.sortColumn())
        b = src.raw(right.row(), self.sortColumn())
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a < b
        return str(a).lower() < str(b).lower()

    def filterAcceptsRow(self, srcRow, parent):
        src = self.sourceModel()
        verdict = src.raw(srcRow, 6)
        if self.mode == 1:
            return verdict == "Exposed"
        if self.mode == 2:
            return verdict in ("Open", "Exposed", "Unknown")
        if self.mode == 3:
            return str(src.raw(srcRow, 0)).lower() == "tcp"
        return True


class CommonPortModel(QAbstractTableModel):
    COLS = ["Port", "Service", "Status", "Security", "Detail"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        port, service, status, security, detail = self.rows[index.row()]
        c = index.column()
        if role == Qt.BackgroundRole:
            if status == "Open" and security == "Exposed":
                return QColor("#3a1a1c")
            if status == "Open":
                return QColor("#33290f")
            return QColor("#14212a" if index.row() % 2 == 0 else "#101a20")
        if role == Qt.ForegroundRole and c == 2:
            return QColor("#6ee7a8" if status == "Open" else "#7d94a0")
        if role == Qt.ForegroundRole and c == 3:
            return _VERDICT_COLOUR.get(security, QColor("#d8e2e8"))
        if role != Qt.DisplayRole:
            return None
        return [str(port), service, status, security, detail][c]

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLS[section]
        return None

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class FirewallDialog(QDialog):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Firewall status")
        self.resize(820, 580)
        lay = QVBoxLayout(self)
        note = QLabel(
            "Read-only snapshot taken through polkit. Nothing was modified."
        )
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)
        body = QPlainTextEdit()
        body.setReadOnly(True)
        body.setFont(QFont("Monospace", 10))
        body.setPlainText(text)
        lay.addWidget(body, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        lay.addWidget(buttons)


class PortsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.listeners = []
        self._scan_results = None
        self._tasks = []
        self._busy = False
        self._build_ui()
        self.refresh(probe=True)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)

        title = QLabel("Ports & exposure")
        title.setObjectName("title")
        root.addWidget(title)
        hint = QLabel(
            "Every listening socket from <code>ss</code>, classified by scope "
            "(loopback / LAN / all interfaces), then checked with a <b>real TLS "
            "handshake</b> or protocol banner so “secured” means something. "
            "Below it, a connect-test for 36 well-known ports gives you an "
            "explicit <b>open / closed</b> answer."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("↻ Refresh & re-probe")
        self.refresh_btn.setObjectName("accent")
        bar.addWidget(self.refresh_btn)
        self.auto_box = QCheckBox("Auto-refresh 5s")
        bar.addWidget(self.auto_box)
        bar.addWidget(QLabel("Show:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All listeners", "Exposed only", "Needs attention", "TCP only",
        ])
        bar.addWidget(self.filter_combo)
        bar.addStretch(1)
        self.fw_btn = QPushButton("🧱 Firewall status (root)")
        bar.addWidget(self.fw_btn)
        root.addLayout(bar)

        self.summary = QLabel("Reading sockets…")
        self.summary.setObjectName("stat")
        root.addWidget(self.summary)

        splitter = QSplitter(Qt.Vertical)

        # ---- listeners -------------------------------------------------
        listen_box = QGroupBox("Listening sockets")
        listen_lay = QVBoxLayout(listen_box)
        self.l_model = ListenerModel(self)
        self.l_proxy = ListenerProxy(self)
        self.l_proxy.setSourceModel(self.l_model)
        self.l_table = QTableView()
        self.l_table.setModel(self.l_proxy)
        self.l_table.setAlternatingRowColors(False)
        self.l_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.l_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.l_table.setSortingEnabled(True)
        self.l_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.l_table.verticalHeader().setVisible(False)
        hh = self.l_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(7, QHeaderView.Stretch)
        # Exposed sorts first alphabetically (E < O < S < U), so the two real
        # problems are always at the top of the table.
        hh.setSortIndicator(6, Qt.AscendingOrder)
        self.l_table.sortByColumn(6, Qt.AscendingOrder)
        listen_lay.addWidget(self.l_table)
        splitter.addWidget(listen_box)

        # ---- common port check ----------------------------------------
        scan_box = QGroupBox("Common port check — TCP connect to 127.0.0.1")
        scan_lay = QVBoxLayout(scan_box)
        top = QHBoxLayout()
        self.scan_btn = QPushButton("▶ Scan %d common ports" % len(COMMON_PORTS))
        top.addWidget(self.scan_btn)
        self.scan_label = QLabel("Not yet scanned")
        self.scan_label.setObjectName("hint")
        top.addWidget(self.scan_label)
        top.addStretch(1)
        scan_lay.addLayout(top)
        self.c_model = CommonPortModel(self)
        self.c_table = QTableView()
        self.c_table.setModel(self.c_model)
        self.c_table.setAlternatingRowColors(True)
        self.c_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.c_table.setSortingEnabled(True)
        self.c_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.c_table.verticalHeader().setVisible(False)
        ch = self.c_table.horizontalHeader()
        ch.setSectionResizeMode(QHeaderView.ResizeToContents)
        ch.setSectionResizeMode(4, QHeaderView.Stretch)
        scan_lay.addWidget(self.c_table)
        splitter.addWidget(scan_box)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        self.refresh_btn.clicked.connect(lambda: self.refresh(probe=True))
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        self.scan_btn.clicked.connect(self.scan)
        self.fw_btn.clicked.connect(self.show_firewall)

        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(lambda: self.refresh(probe=False, auto=True))
        self.timer.start()

    # -- data -------------------------------------------------------------
    def refresh(self, probe=True, auto=False):
        if self._busy:
            return
        if auto and not self.auto_box.isChecked():
            return
        self._busy = True
        if not auto:
            self.summary.setText("Reading sockets…")
        do_probe = probe

        def work():
            socks = listening_sockets()
            if do_probe:
                tcp = [s for s in socks
                       if s["proto"] == "tcp" and s["port"]]
                with ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(probe_listener, tcp))
                for sock, res in zip(tcp, results):
                    sock["probe"] = res
            return socks

        t = Task(work)
        t.ok.connect(self._loaded)
        t.failed.connect(self._failed)
        self._tasks.append(t)
        t.start()

    def _loaded(self, socks):
        self._busy = False
        for sock in socks:
            sock["verdict"], sock["detail"] = verdict_for(sock, sock["probe"])
        socks.sort(key=lambda s: (s["proto"], -s["port"]))
        self.listeners = socks
        self.l_model.set_rows(socks)
        self._apply_filter()
        self._update_summary()
        if self._scan_results is not None:
            self._render_common()

    def _failed(self, msg):
        self._busy = False
        self.summary.setText("Socket error: " + msg)
        self.summary.setObjectName("bad")
        self.summary.style().unpolish(self.summary)
        self.summary.style().polish(self.summary)

    def _apply_filter(self, *_):
        self.l_proxy.mode = self.filter_combo.currentIndex()
        self.l_proxy.invalidate()

    def _update_summary(self):
        socks = self.listeners
        counts = dict.fromkeys(_VERDICTS, 0)
        for s in socks:
            counts[s["verdict"]] = counts.get(s["verdict"], 0) + 1
        tcp = sum(1 for s in socks if s["proto"] == "tcp")
        loop = sum(1 for s in socks if s["scope"] == "Loopback")
        exposed = [s for s in socks if s["verdict"] == "Exposed"]
        text = (
            "%d listeners · %d TCP · %d loopback · %d secured · %d local · "
            "%d open · %d EXPOSED"
            % (len(socks), tcp, loop, counts["Secured"], counts.get("Local", 0),
               counts["Open"], counts["Exposed"])
        )
        self.summary.setText(text)
        if exposed:
            self.summary.setObjectName("bad")
        elif counts["Open"]:
            self.summary.setObjectName("warn")
        else:
            self.summary.setObjectName("good")
        self.summary.style().unpolish(self.summary)
        self.summary.style().polish(self.summary)
        self._summary_base = text

    # -- common port scan -------------------------------------------------
    def scan(self):
        self.scan_btn.setEnabled(False)
        self.scan_label.setText("Scanning…")

        def work():
            return scan_common_ports()

        t = Task(work)
        t.ok.connect(self._scan_done)
        t.failed.connect(self._scan_failed)
        self._tasks.append(t)
        t.start()

    def _scan_done(self, results):
        self._scan_results = results
        self.scan_btn.setEnabled(True)
        self._render_common()

    def _scan_failed(self, msg):
        self.scan_btn.setEnabled(True)
        self.scan_label.setText("Scan failed: " + msg)

    def _render_common(self):
        by_port = {s["port"]: s for s in self.listeners if s["proto"] == "tcp"}
        rows = []
        open_count = 0
        for port, desc, reachable in self._scan_results:
            sock = by_port.get(port)
            if reachable or sock:
                status = "Open"
                open_count += 1
                if sock:
                    security, detail = sock["verdict"], sock["detail"]
                else:
                    security = "Unknown"
                    detail = "accepted a connection on 127.0.0.1:%d but no " \
                             "matching ss entry" % port
            else:
                status = "Closed"
                security = "—"
                detail = "nothing listening on 127.0.0.1:%d" % port
            rows.append((port, desc, status, security, detail))
        self.c_model.set_rows(rows)
        self.scan_label.setText(
            "%d open · %d closed of %d checked"
            % (open_count, len(rows) - open_count, len(rows))
        )

    # -- firewall ----------------------------------------------------------
    def show_firewall(self):
        self.fw_btn.setEnabled(False)
        base = self._summary_base if hasattr(self, "_summary_base") else ""
        self.summary.setText("Waiting for polkit authentication…")
        self.summary.setObjectName("warn")

        def work():
            return firewall_report()

        t = Task(work)
        t.ok.connect(self._fw_done)
        t.failed.connect(self._fw_failed)
        self._tasks.append(t)
        self._tasks_base = base
        t.start()

    def _fw_done(self, result):
        self.fw_btn.setEnabled(True)
        rc, out, err = result
        text = out if rc == 0 else "(pkexec rc=%d)\n%s" % (rc, (err or out))
        if not text.strip():
            text = "(no output)"
        self._update_summary()
        dlg = FirewallDialog(text, self)
        dlg.exec()

    def _fw_failed(self, msg):
        self.fw_btn.setEnabled(True)
        self._update_summary()
        QMessageBox.warning(self, "Firewall status", msg)


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1280, 820)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.proc_tab = ProcessesTab()
        self.res_tab = ResourcesTab()
        self.ports_tab = PortsTab()
        self.docker_tab = DockerTab()
        self.snap_tab = SnapshotsTab()
        self.disk_tab = DiskTab()
        self.tabs.addTab(self.proc_tab, "⚡ Processes")
        self.tabs.addTab(self.res_tab, "📊 Resources")
        self.tabs.addTab(self.ports_tab, "🔌 Ports")
        self.tabs.addTab(self.docker_tab, "🐳 Docker")
        self.tabs.addTab(self.snap_tab, "📸 Snapshots")
        self.tabs.addTab(self.disk_tab, "💾 Disk")
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(
            "Parrot Janitor · Polkit agent available for root actions · "
            "docker group: yes"
        )

        self.tabs.currentChanged.connect(self._on_tab)
        refresh_sc = QShortcut(QKeySequence.Refresh, self)
        refresh_sc.activated.connect(lambda: self._on_tab(self.tabs.currentIndex()))

        # Deferred shutdown: never block the UI in closeEvent waiting for
        # background Tasks (a du/find scan can run for minutes). Instead ignore
        # the close, drain them, then close again.
        self._close_timer = QTimer(self)
        self._close_timer.setInterval(250)
        self._close_timer.timeout.connect(self._poll_close)

    def _on_tab(self, i):
        if i == 3:
            self.docker_tab.refresh()
        elif i == 5:
            self.disk_tab.refresh_sizes()

    def _background_tasks(self):
        for tab in (self.proc_tab, self.ports_tab, self.docker_tab,
                    self.snap_tab, self.disk_tab):
            for t in tab._tasks:
                yield t

    def closeEvent(self, event):
        self.proc_tab.shutdown()
        self.res_tab.shutdown()
        # A running QThread must never be destroyed (Qt aborts with SIGABRT),
        # so defer the close until every background Task has finished.
        # Each Task is bounded by the timeouts in sh(), so this always resolves.
        running = [t for t in self._background_tasks() if t.isRunning()]
        if not running:
            self._close_timer.stop()
            super().closeEvent(event)
            return
        event.ignore()
        self.statusBar().showMessage(
            "Finishing %d background task(s) before quitting…" % len(running)
        )
        self._close_timer.start()

    def _poll_close(self):
        running = [t for t in self._background_tasks() if t.isRunning()]
        if running:
            self.statusBar().showMessage(
                "Finishing %d background task(s)…" % len(running)
            )
            return
        self._close_timer.stop()
        self.close()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def smoke_test():
    """Headless self-check: exercise the data layer without a window."""
    print("== PySide6 import OK ==")
    print("== process sampling ==")
    rows = sample_processes()
    print("   %d processes" % len(rows))
    tr = RunawayTracker()
    tr.update(rows)
    print("   hot=%d runaway=%d" % (
        sum(1 for r in rows if r.verdict == "HOT"),
        sum(1 for r in rows if r.verdict == "RUNAWAY"),
    ))
    top = sorted(rows, key=lambda r: r.cpu, reverse=True)[:3]
    for r in top:
        print("   %-7d %5.1f%%  %s" % (r.pid, r.cpu, r.short[:80]))

    print("== docker ==")
    try:
        items = docker_ps()
        print("   %d containers" % len(items))
        print("   stats keys: %d" % len(docker_stats()))
    except Exception as e:
        print("   skipped: %s" % e)

    print("== helpers ==")
    print("   human_bytes(10792257) =", human_bytes(10792257))
    print("   human_duration(2664)  =", human_duration(2664))
    print("   describe grep         =", describe_process("/usr/bin/grep", "grep x", {}))

    print("== resources ==")
    t0 = read_cpu_times()
    time.sleep(0.4)
    t1 = read_cpu_times()
    print("   aggregate %.1f%% busy over %d cores" % (
        _delta_pct((t0[0], t0[1]), (t1[0], t1[1])), len(t1[2])))
    m = read_meminfo()
    print("   mem total=%s available=%s" % (
        human_bytes(m.get("MemTotal", 0)), human_bytes(m.get("MemAvailable", 0))))
    print("   load:", "%.2f %.2f %.2f" % read_loadavg()[:3],
          "| runnable:", read_loadavg()[3])
    temps = read_temps()
    print("   temps:", ", ".join("%s %.0fC" % (l, c) for l, c in temps) or "none")

    print("== ports ==")
    socks = listening_sockets()
    print("   %d listeners (%d tcp)" % (
        len(socks), sum(1 for s in socks if s["proto"] == "tcp")))
    print("   split_addr:", split_addr("0.0.0.0:22"), split_addr("[::]:22"),
          split_addr("192.168.1.5%virbr0:53"))
    print("   scopes:", sorted({s["scope"] for s in socks}))
    tcp = [s for s in socks if s["proto"] == "tcp"][:6]
    for s in tcp:
        s["probe"] = probe_listener(s, timeout=0.6)
        s["verdict"], s["detail"] = verdict_for(s, s["probe"])
        print("   %-5d %-10s %-15s -> %-8s %s" % (
            s["port"], s["service"] or "-", s["scope"], s["verdict"], s["detail"]))
    scan = scan_common_ports()
    print("   common-port scan: %d open of %d" % (
        sum(1 for r in scan if r[2]), len(scan)))
    print("   open ports:", [r[1] for r in scan if r[2]])

    print("== Qt widgets construct ==")
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    win.show()
    app.processEvents()

    # Drain background work before teardown: a QThread destroyed while
    # running makes Qt abort with SIGABRT. Every Task is bounded by the
    # timeouts in sh(), so this loop always terminates.
    win.proc_tab.shutdown()
    win.res_tab.shutdown()
    deadline = time.time() + 120
    while time.time() < deadline:
        app.processEvents()
        if not any(t.isRunning() for t in win._background_tasks()):
            break
        time.sleep(0.05)
    for t in win._background_tasks():
        if t.isRunning():
            t.wait(30000)
    win.close()
    print("   OK")
    return 0


def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--smoke", action="store_true",
                    help="run a headless self-check and exit")
    args = ap.parse_args()

    if args.smoke:
        return smoke_test()

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
