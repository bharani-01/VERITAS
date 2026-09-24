#!/usr/bin/env python3
"""
Tkinter lab UI for VERITAS security-traffic simulation.

AUTHORIZED USE ONLY against your own VERITAS instance.
"""

from __future__ import annotations

import random
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))
from simulate_security_traffic import ATTACK_LABELS, _probes, _send  # noqa: E402

DEFAULT_URL = "https://veritas.trackifyapp.co.in/"

ATTACK_OPTIONS = (
    ("sqli", "SQL injection"),
    ("xss", "Cross-site scripting (XSS)"),
    ("cmd_inject", "OS command injection"),
    ("path_traversal", "Path traversal / LFI"),
    ("ssrf", "SSRF (internal/metadata URL)"),
    ("ssti", "Server-side template injection"),
    ("open_redirect", "Open redirect"),
    ("header_abuse", "Header abuse / Host spoof / CRLF"),
    ("csrf", "CSRF (cookie + state change)"),
    ("scanner", "Scanner User-Agent"),
    ("auth", "Auth anomaly (failed login)"),
    ("weak_headers", "Weak response headers probe"),
    ("clean", "Clean baseline"),
)


class SimulatorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("VERITAS Lab — Attack Traffic Simulator")
        self.geometry("780x640")
        self.minsize(680, 520)

        self._stop = threading.Event()
        self._worker: threading.Thread | None = None

        self.url_var = tk.StringVar(value=DEFAULT_URL)
        self.count_var = tk.IntVar(value=50)
        self.delay_var = tk.DoubleVar(value=0.12)
        self.own_var = tk.BooleanVar(value=False)
        self.attack_vars = {key: tk.BooleanVar(value=True) for key, _ in ATTACK_OPTIONS}

        self._build()

    def _build(self) -> None:
        pad = {"padx": 10, "pady": 6}
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text="Target URL (your VERITAS instance)").pack(anchor=tk.W)
        ttk.Entry(root, textvariable=self.url_var).pack(fill=tk.X, **pad)

        opts = ttk.LabelFrame(root, text="Simulate attacks", padding=10)
        opts.pack(fill=tk.X, **pad)

        btn_row = ttk.Frame(opts)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(btn_row, text="Select all", command=lambda: self._set_all(True)).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Clear all", command=lambda: self._set_all(False)).pack(
            side=tk.LEFT, padx=6
        )

        grid = ttk.Frame(opts)
        grid.pack(fill=tk.X)
        for i, (key, label) in enumerate(ATTACK_OPTIONS):
            ttk.Checkbutton(grid, text=label, variable=self.attack_vars[key]).grid(
                row=i // 2, column=i % 2, sticky=tk.W, padx=(0, 16), pady=2
            )

        row = ttk.Frame(root)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text="Requests").pack(side=tk.LEFT)
        ttk.Spinbox(row, from_=1, to=500, textvariable=self.count_var, width=8).pack(
            side=tk.LEFT, padx=(6, 16)
        )
        ttk.Label(row, text="Delay (s)").pack(side=tk.LEFT)
        ttk.Spinbox(
            row, from_=0.0, to=5.0, increment=0.05, textvariable=self.delay_var, width=8
        ).pack(side=tk.LEFT, padx=6)

        ttk.Checkbutton(
            root,
            text="I own this target (required)",
            variable=self.own_var,
        ).pack(anchor=tk.W, **pad)

        btns = ttk.Frame(root)
        btns.pack(fill=tk.X, **pad)
        self.start_btn = ttk.Button(btns, text="Start", command=self._start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(btns, text="Stop", command=self._request_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)

        ttk.Label(root, text="Log").pack(anchor=tk.W)
        self.log = scrolledtext.ScrolledText(root, height=16, wrap=tk.WORD, state=tk.DISABLED)
        self.log.pack(fill=tk.BOTH, expand=True, **pad)

        ttk.Label(
            root,
            text="Lab only — after run, open /admin/security → Run AI agent.",
            foreground="#555",
        ).pack(anchor=tk.W)

    def _set_all(self, value: bool) -> None:
        for var in self.attack_vars.values():
            var.set(value)

    def _append(self, line: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _set_running(self, running: bool) -> None:
        self.start_btn.configure(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.configure(state=tk.NORMAL if running else tk.DISABLED)

    def _start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        if not self.own_var.get():
            messagebox.showwarning(
                "Confirmation required",
                "Check “I own this target” before running.",
            )
            return
        selected = [k for k, v in self.attack_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("No attacks selected", "Enable at least one checkbox.")
            return
        unknown = set(selected) - set(ATTACK_LABELS)
        if unknown:
            messagebox.showerror("Unknown attack", f"Unsupported: {sorted(unknown)}")
            return
        base = self.url_var.get().strip()
        if not base:
            messagebox.showerror("Missing URL", "Enter a target URL.")
            return
        try:
            count = int(self.count_var.get())
            delay = float(self.delay_var.get())
        except (tk.TclError, TypeError, ValueError):
            messagebox.showerror("Invalid input", "Check request count and delay.")
            return
        if count < 1:
            messagebox.showerror("Invalid input", "Request count must be ≥ 1.")
            return

        self._stop.clear()
        self._set_running(True)
        self._append(f"Target: {base}")
        self._append(f"Attacks: {', '.join(selected)} · count={count} · delay={delay}s")
        self._append("-" * 56)

        self._worker = threading.Thread(
            target=self._run,
            args=(base, selected, count, delay),
            daemon=True,
        )
        self._worker.start()

    def _request_stop(self) -> None:
        self._stop.set()
        self._append("Stopping…")

    def _run(self, base: str, selected: list[str], count: int, delay: float) -> None:
        pool = [p for p in _probes() if p.label in selected]
        if not pool:
            self.after(0, lambda: self._finish("No matching probes."))
            return

        rng = random.Random()
        tallies: dict[str, int] = {}
        status_tallies: dict[str, int] = {}

        for i in range(1, count + 1):
            if self._stop.is_set():
                break
            probe = rng.choice(pool)
            status, detail = _send(base, probe, timeout=8.0)
            tallies[probe.label] = tallies.get(probe.label, 0) + 1
            key = str(status) if status else "err"
            status_tallies[key] = status_tallies.get(key, 0) + 1
            q = f"?{probe.query}" if probe.query else ""
            line = (
                f"[{i:03d}/{count}] {probe.label:14} {probe.method:6} "
                f"{probe.path}{q[:36]} → {status or 'ERR'} {detail}"
            )
            self.after(0, lambda l=line: self._append(l))
            if delay > 0 and i < count and not self._stop.is_set():
                self._stop.wait(delay)

        summary = (
            f"Done. By type: {dict(sorted(tallies.items()))} · "
            f"status: {dict(sorted(status_tallies.items()))}"
        )
        self.after(0, lambda: self._finish(summary))

    def _finish(self, message: str) -> None:
        self._append("-" * 56)
        self._append(message)
        self._append("Next: /admin/security → refresh → Run AI agent.")
        self._append("")
        self._set_running(False)


def main() -> None:
    app = SimulatorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
