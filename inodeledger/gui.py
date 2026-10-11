"""Native, offline desktop investigator. All filesystem work runs off the UI thread."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .store import Ledger, default_home

BG, PANEL, TEXT, MUTED, ACCENT = "#101720", "#18222f", "#e5edf5", "#91a3b9", "#62d6b0"


class App:
    def __init__(self, root, home=None):
        self.root, self.home = root, str(home or default_home())
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.results = queue.Queue()
        self.busy = False
        self.closed = False
        self.selected_path = None
        self.root_paths, self.snapshot_ids = {}, {}
        root.title("InodeLedger · Filesystem history")
        root.geometry("1320x830")
        root.minsize(1000, 650)
        root.configure(bg=BG)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=("Segoe UI", 23, "bold"))
        style.configure("TButton", background=PANEL, foreground=TEXT, padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#2c4055")])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#223143", foreground=MUTED, padding=8)
        style.map("Treeview", background=[("selected", "#285044")], foreground=[("selected", "#ffffff")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, padding=(18, 10))
        style.map("TNotebook.Tab", background=[("selected", "#285044")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT)

        header = ttk.Frame(root, padding=(25, 20))
        header.pack(fill="x")
        ttk.Label(header, text="◈  InodeLedger", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="EVERY FILE HAS A HISTORY", style="Muted.TLabel").pack(side="left", padx=25)
        ttk.Button(header, text="Refresh", command=self.refresh).pack(side="right")
        self.counts = tk.StringVar(value="Opening local ledger…")
        ttk.Label(root, textvariable=self.counts, font=("Segoe UI", 12), padding=(28, 10)).pack(fill="x")
        tk.Label(root, text="REDUCED COVERAGE  ·  Observed metadata only  ·  Actor and exact change time unknown", bg="#352d1c", fg="#f2cf88", anchor="w", padx=28, pady=10).pack(fill="x", pady=(5, 15))

        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True, padx=22)
        self.explorer = ttk.Frame(tabs, padding=12)
        self.activity = ttk.Frame(tabs, padding=12)
        self.snapshots_page = ttk.Frame(tabs, padding=12)
        self.incidents_page = ttk.Frame(tabs, padding=12)
        self.health_page = ttk.Frame(tabs, padding=12)
        for page, title in [(self.explorer, "Explorer"), (self.activity, "Activity"), (self.snapshots_page, "Snapshots & recovery"), (self.incidents_page, "Incidents"), (self.health_page, "Health & evidence")]:
            tabs.add(page, text=title)
        self.build_explorer()
        self.build_activity()
        self.build_snapshots()
        ttk.Label(self.incidents_page, text="Permission-change clusters by root and observation time. These groups do not prove a common actor or command.", style="Muted.TLabel", padding=6).pack(anchor="w")
        ttk.Button(self.incidents_page, text="Analyze recorded permission changes", command=self.incidents).pack(anchor="w", pady=6)
        self.incident_text = self.textbox(self.incidents_page)
        bar = ttk.Frame(self.health_page)
        bar.pack(fill="x")
        ttk.Button(bar, text="Verify integrity", command=lambda: self.submit(lambda l: l.verify(), self.show_health)).pack(side="left", padx=4)
        ttk.Button(bar, text="Export mirrored audit logs", command=lambda: self.submit(lambda l: l.materialize(), self.show_health)).pack(side="left", padx=4)
        ttk.Button(bar, text="Capability report", command=lambda: self.submit(lambda l: l.status(), self.show_health)).pack(side="left", padx=4)
        ttk.Button(bar, text="Start background monitor", command=self.start_agent).pack(side="left", padx=4)
        ttk.Button(bar, text="Stop monitor", command=lambda: self.submit(lambda l: l.stop_agent(), self.show_health)).pack(side="left", padx=4)
        self.health_text = self.textbox(self.health_page)
        self.status = tk.StringVar(value="Local · Offline · No file contents retained")
        ttk.Label(root, textvariable=self.status, style="Muted.TLabel", padding=(24, 10)).pack(fill="x")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)
        self.refresh()

    def textbox(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=10)
        text = tk.Text(frame, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", padx=16, pady=14, wrap="word", font=("Consolas", 10), state="disabled")
        scroll = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        return text

    def table(self, parent, columns, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for c, width in zip(columns, widths):
            tree.heading(c, text=c)
            tree.column(c, width=width, minwidth=50)
        scrollbar = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    def build_explorer(self):
        toolbar = ttk.Frame(self.explorer)
        toolbar.pack(fill="x", pady=(0, 12))
        ttk.Button(toolbar, text="+ Monitor folder", command=self.add_root).pack(side="left")
        ttk.Button(toolbar, text="Reconcile now", command=self.reconcile).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Investigate file…", command=self.pick_file).pack(side="left")
        self.search = tk.StringVar()
        entry = ttk.Entry(toolbar, textvariable=self.search, width=26)
        entry.pack(side="right", padx=6)
        entry.bind("<Return>", lambda _: self.refresh())
        ttk.Label(toolbar, text="Filter paths", style="Muted.TLabel").pack(side="right")
        panes = ttk.Panedwindow(self.explorer, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left, middle, right = ttk.Frame(panes), ttk.Frame(panes), ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(middle, weight=3)
        panes.add(right, weight=3)
        ttk.Label(left, text="MONITORED ROOTS", style="Muted.TLabel", padding=6).pack(anchor="w")
        self.roots_tree = self.table(left, ("Directory",), (200,))
        self.roots_tree.bind("<<TreeviewSelect>>", self.filter_root)
        ttk.Button(left, text="Stop monitoring selected", command=self.remove_root).pack(fill="x", pady=8)
        ttk.Label(middle, text="RECORDED FILES · FIRST 500 MATCHES", style="Muted.TLabel", padding=6).pack(anchor="w")
        self.files_tree = self.table(middle, ("Path", "Mode", "Type"), (300, 60, 75))
        self.files_tree.bind("<<TreeviewSelect>>", self.select_file)
        self.detail_title = tk.StringVar(value="Select a file to investigate")
        ttk.Label(right, textvariable=self.detail_title, padding=6, wraplength=350).pack(anchor="w")
        actions = ttk.Frame(right)
        actions.pack(fill="x")
        ttk.Button(actions, text="Analyze", command=self.analyze).pack(side="left", padx=4)
        ttk.Button(actions, text="Malware scan", command=self.scan).pack(side="left", padx=4)
        ttk.Button(actions, text="History", command=self.history).pack(side="left", padx=4)
        self.details = self.textbox(right)

    def build_activity(self):
        ttk.Label(self.activity, text="Observation timestamps are UTC. Before values are the last recorded state, not guaranteed syscall pre-state.", style="Muted.TLabel", padding=6).pack(anchor="w")
        self.events_tree = self.table(self.activity, ("Observed at", "Event", "Path", "Before → after"), (200, 150, 460, 160))
        self.events_tree.bind("<<TreeviewSelect>>", self.select_event)
        self.event_detail = self.textbox(self.activity)

    def build_snapshots(self):
        actions = ttk.Frame(self.snapshots_page)
        actions.pack(fill="x", pady=(0, 10))
        ttk.Button(actions, text="Capture snapshot", command=self.snapshot).pack(side="left")
        ttk.Button(actions, text="Compare latest two", command=self.diff).pack(side="left", padx=6)
        ttk.Button(actions, text="Preview mode recovery", command=self.plan).pack(side="left")
        ttk.Label(self.snapshots_page, text="Recovery is a preview here. Linux application requires the CLI's explicit --confirm flag.", style="Muted.TLabel", padding=6).pack(anchor="w")
        self.snapshots_tree = self.table(self.snapshots_page, ("Name", "Captured at", "Root", "Coverage"), (200, 220, 450, 100))
        self.recovery_text = self.textbox(self.snapshots_page)

    def submit(self, work, done):
        if self.busy or self.closed:
            self.status.set("An operation is already running. Please wait.")
            return
        self.busy = True
        self.status.set("Working…")
        def execute():
            ledger = None
            try:
                ledger = Ledger(self.home)
                value = work(ledger)
                self.results.put((done, value, None))
            except Exception as exc:
                self.results.put((done, None, str(exc)))
            finally:
                if ledger:
                    ledger.close()
        self.executor.submit(execute)

    def poll(self):
        try:
            while True:
                done, value, error = self.results.get_nowait()
                self.busy = False
                if error:
                    self.status.set("Operation failed")
                    messagebox.showerror("InodeLedger", error, parent=self.root)
                else:
                    self.status.set("Ready · Local evidence · No cloud connections")
                    done(value)
        except queue.Empty:
            pass
        if not self.closed:
            self.root.after(100, self.poll)

    def refresh(self):
        search = self.search.get()
        self.submit(lambda l: (l.status(), l.files(search), l.events(), l.snapshots()), self.render)

    def render(self, data):
        health, files, events, snapshots = data
        self.counts.set(f"{health['objects']:,} tracked objects     /     {health['events']:,} recorded events     /     {sum(r['enabled'] for r in health['roots'])} active roots     /     {health['gaps']} coverage notices")
        for tree in (self.roots_tree, self.files_tree, self.events_tree, self.snapshots_tree):
            tree.delete(*tree.get_children())
        self.root_paths = {}
        for r in health["roots"]:
            if r["enabled"]:
                iid = self.roots_tree.insert("", "end", values=(r["path"],))
                self.root_paths[iid] = r["path"]
        for r in files:
            self.files_tree.insert("", "end", values=(r["path"], r["metadata"]["octal"], r["metadata"]["kind"]))
        self.event_rows = {}
        for e in events:
            before, after = e.get("before") or {}, e.get("after") or {}
            iid = self.events_tree.insert("", "end", values=(e["time"][:26], e["kind"], e["path"] or "—", before.get("octal", "?") + " → " + after.get("octal", "?")))
            self.event_rows[iid] = e
        self.snapshot_ids = {}
        for s in snapshots:
            iid = self.snapshots_tree.insert("", "end", values=(s["name"], s["time"][:26], s["root"], "Complete scan" if s["complete"] else "Partial"))
            self.snapshot_ids[iid] = s["id"]
        self.show_health(health)

    @staticmethod
    def write(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=True))
        widget.configure(state="disabled")

    def show_health(self, result):
        self.write(self.health_text, result)

    def incidents(self):
        from .investigation import incidents
        self.submit(lambda l: incidents(l), lambda value: self.write(self.incident_text, value if value else "No recorded permission clusters meet the threshold (100 changes in 60 seconds), and no high-risk permission transitions were recorded."))

    def start_agent(self):
        def launch(ledger):
            from .agent import agent_lock
            # A second agent also checks this lock when it starts.
            with agent_lock(ledger.home):
                pass
            log = ledger.home / "agent.log"
            from .metadata import reject_links
            reject_links(log)
            with log.open("ab") as output:
                process = subprocess.Popen([sys.executable, "-m", "inodeledger.agent", "--home", self.home], stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                           start_new_session=os.name != "nt")
            return {"status": "Background monitor launched; refresh to inspect its heartbeat", "pid": process.pid, "log": str(log), "interval_seconds": 10}
        self.submit(launch, self.show_health)

    def add_root(self):
        path = filedialog.askdirectory(title="Choose a directory to monitor", parent=self.root)
        if path:
            self.submit(lambda l: l.add_root(path), lambda _: self.refresh())

    def filter_root(self, _=None):
        selection = self.roots_tree.selection()
        if selection and selection[0] in self.root_paths:
            path = self.root_paths[selection[0]]
            self.search.set(path)
            self.submit(lambda l: l.files(path), self.render_files)

    def render_files(self, files):
        self.files_tree.delete(*self.files_tree.get_children())
        for r in files:
            self.files_tree.insert("", "end", values=(r["path"], r["metadata"]["octal"], r["metadata"]["kind"]))

    def remove_root(self):
        selection = self.roots_tree.selection()
        if selection:
            path = self.root_paths[selection[0]]
            self.submit(lambda l: l.remove_root(path), lambda _: self.refresh())

    def reconcile(self):
        self.submit(lambda l: [l.reconcile(r["path"]) for r in l.roots() if r["enabled"]], lambda _: self.refresh())

    def select_file(self, _=None):
        selection = self.files_tree.selection()
        if selection:
            self.selected_path = self.files_tree.item(selection[0], "values")[0]
            self.detail_title.set(Path(self.selected_path).name)
            self.history()

    def pick_file(self):
        path = filedialog.askopenfilename(parent=self.root)
        if path:
            self.selected_path = path
            self.detail_title.set(Path(path).name)
            self.history()

    def history(self):
        if self.selected_path:
            path = self.selected_path
            def result(events):
                self.write(self.details, events if events else "No historical record. Prior permissions and activity are unknown. Use Analyze to inspect the current file.")
            self.submit(lambda l: l.events(path=path), result)

    def analyze(self):
        if self.selected_path:
            from .security import analyze
            path = self.selected_path
            self.submit(lambda _: analyze(path), lambda value: self.write(self.details, value))

    def scan(self):
        if self.selected_path:
            from .security import scan
            path = self.selected_path
            def work(ledger):
                result = scan(path)
                with ledger.transaction():
                    ledger.event("malware_scan", path, source="analysis", result=result)
                return result
            self.submit(work, lambda value: self.write(self.details, value))

    def select_event(self, _=None):
        selection = self.events_tree.selection()
        if selection and selection[0] in self.event_rows:
            self.write(self.event_detail, self.event_rows[selection[0]])

    def snapshot(self):
        selected = self.roots_tree.selection()
        path = self.root_paths.get(selected[0]) if selected else None
        if not path:
            path = filedialog.askdirectory(title="Choose an already monitored root", parent=self.root)
        if path:
            name = simpledialog.askstring("Snapshot", "Snapshot name", initialvalue="Manual snapshot", parent=self.root)
            if name:
                self.submit(lambda l: l.reconcile(path, name), lambda _: self.refresh())

    def diff(self):
        selected = self.snapshots_tree.selection()
        if not selected:
            self.write(self.recovery_text, "Select a snapshot. Its root's latest two snapshots will be compared.")
            return
        sid = self.snapshot_ids[selected[0]]
        def work(ledger):
            snapshots = ledger.snapshots()
            root = next(s["root"] for s in snapshots if s["id"] == sid)
            matches = [s for s in snapshots if s["root"] == root]
            if len(matches) < 2:
                raise ValueError("Capture at least two snapshots of this root")
            return ledger.diff(matches[1]["id"], matches[0]["id"])
        self.submit(work, lambda value: self.write(self.recovery_text, value))

    def plan(self):
        selected = self.snapshots_tree.selection()
        if selected:
            from .recovery import plan
            sid = self.snapshot_ids[selected[0]]
            self.submit(lambda l: plan(l, sid), lambda value: self.write(self.recovery_text, value))
        else:
            self.write(self.recovery_text, "Select the historical snapshot to use as the recovery target.")

    def close(self):
        if self.busy:
            self.status.set("Wait for the current filesystem operation to finish before closing.")
            return
        self.closed = True
        self.executor.shutdown(wait=False)
        self.root.destroy()


def main(home=None):
    root = tk.Tk()
    App(root, home)
    root.mainloop()


if __name__ == "__main__":
    main()
