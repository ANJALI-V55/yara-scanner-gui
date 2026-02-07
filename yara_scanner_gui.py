import os
import shutil
import threading
import time
import csv

import yara
import os

os.environ["TCL_LIBRARY"] = (
    r"C:\Users\vaishnavi reddy\AppData\Local\Programs\Python\Python313\tcl\tcl8.6"
)
os.environ["TK_LIBRARY"] = (
    r"C:\Users\vaishnavi reddy\AppData\Local\Programs\Python\Python313\tcl\tk8.6"
)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import fitz  # pymupdf
from PIL import Image, ImageTk
import io


# =============== CONFIG ===============

DEFAULT_RULES_FILE = "malware_rules.yara"
QUARANTINE_DIR = "quarantine"
LOG_FILE = "scan_log.csv"
LOGO_IMAGE = "company_logo.png"
PROJECT_PDF = "project information.pdf"


class MalwareScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Window basics
        self.title("Cyber Shield - YARA Malware Scanner")
        self.geometry("1000x600")
        self.minsize(900, 500)

        # Modern dark theme colors
        self.bg_color = "#111827"  # dark background
        self.card_color = "#1f2933"  # card / panel
        self.accent = "#3b82f6"  # blue
        self.text_primary = "#e5e7eb"
        self.text_muted = "#9ca3af"

        self.configure(bg=self.bg_color)
        # --- LOGO HANDLING ---
        self.logo_img = None  # for sidebar logo
        self._load_logo()  # tries to load PNG + window icon

        # State
        self.rules = None
        self.rules_path = DEFAULT_RULES_FILE
        self.total_scanned = 0
        self.total_malicious = 0
        self.total_clean = 0

        # ---- basic scheduler state ----
        self.sched_thread = None
        self.sched_stop_event = threading.Event()
        self.sched_folder = None
        self.sched_interval = 0  # in minutes

        # Ensure quarantine & log exist
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Timestamp", "Path", "Status", "Matched_Rules", "Quarantined"]
                )

        # Build UI
        self._build_layout()

        # Load default rules if exists
        self._auto_load_rules()

    # =============== LOGO LOADING ===============

    def _load_logo(self):
        """
        Loads company logo for:
        - window icon (if ICO exists)
        - sidebar top image (PNG)
        If files are missing, app still runs normally.
        """

        # Sidebar logo (PNG) – optional
        if os.path.exists(LOGO_IMAGE):
            try:
                self.logo_img = tk.PhotoImage(file=LOGO_IMAGE)
            except Exception:
                self.logo_img = None

    # =============== UI LAYOUT ===============

    def _build_layout(self):
        # Left sidebar
        sidebar = tk.Frame(self, bg="#020617", width=200)
        sidebar.pack(side="left", fill="y")
        # --- Company logo at top (if available) ---
        if self.logo_img is not None:
            logo_label = tk.Label(sidebar, image=self.logo_img, bg="#020617")
            logo_label.pack(pady=(15, 5))

        title_label = tk.Label(
            sidebar,
            text="CYBER SHIELD",
            fg=self.text_primary,
            bg="#020617",
            font=("Segoe UI", 16, "bold"),
        )
        title_label.pack(pady=(20, 5))

        subtitle = tk.Label(
            sidebar,
            text="YARA Malware Scanner",
            fg=self.text_muted,
            bg="#020617",
            font=("Segoe UI", 9),
        )
        subtitle.pack(pady=(0, 20))

        # Buttons list
        btn_style = {
            "font": ("Segoe UI", 10, "bold"),
            "bd": 0,
            "relief": "flat",
            "fg": self.text_primary,
            "bg": "#020617",
            "activebackground": "#111827",
            "activeforeground": self.text_primary,
            "anchor": "w",
            "padx": 20,
            "pady": 8,
        }

        def make_btn(text, command):
            frame = tk.Frame(sidebar, bg="#020617")
            frame.pack(fill="x")
            btn = tk.Button(frame, text=text, command=command, **btn_style)
            btn.pack(fill="x")
            sep = tk.Frame(sidebar, height=1, bg="#111827")
            sep.pack(fill="x", padx=10, pady=(0, 2))
            return btn

        make_btn("📜 Load Rules", self.load_rules_dialog)
        make_btn("✏️ Edit Rules", self.edit_rules)
        make_btn("📁 Scan File", self.scan_file_dialog)
        make_btn("🗂️ Scan Folder", self.scan_folder_dialog)
        make_btn("🧊 Manage Quarantine", self.open_quarantine_folder)
        make_btn("⏰ Schedule Scan (Basic)", self.schedule_scan_basic)
        make_btn("❌ Exit", self.quit)
        make_btn("ℹ Project Info ", self.open_project_info_in_ui)

        # Main area
        main = tk.Frame(self, bg=self.bg_color)
        main.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Top stats card
        stats_card = tk.Frame(main, bg=self.card_color, bd=0, relief="flat")
        stats_card.pack(fill="x", pady=(0, 10))

        self.status_label = tk.Label(
            stats_card,
            text="Status: Idle (No rules loaded)",
            bg=self.card_color,
            fg=self.text_primary,
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        self.status_label.pack(fill="x", padx=10, pady=(8, 0))

        self.rules_label = tk.Label(
            stats_card,
            text=f"Rules file: {self.rules_path if os.path.exists(self.rules_path) else 'Not loaded'}",
            bg=self.card_color,
            fg=self.text_muted,
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.rules_label.pack(fill="x", padx=10, pady=(0, 8))

        # Stats row
        stats_row = tk.Frame(stats_card, bg=self.card_color)
        stats_row.pack(fill="x", padx=10, pady=(0, 10))

        self.total_label = self._stat_chip(stats_row, "Total Scanned", "0")
        self.clean_label = self._stat_chip(stats_row, "Clean Files", "0")
        self.mal_label = self._stat_chip(stats_row, "Malicious Files", "0")

        # Log area card
        log_card = tk.Frame(main, bg=self.card_color, bd=0, relief="flat")
        log_card.pack(fill="both", expand=True)

        log_header = tk.Label(
            log_card,
            text="Scan Log",
            bg=self.card_color,
            fg=self.text_primary,
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        log_header.pack(fill="x", padx=10, pady=(8, 0))

        # Treeview for modern table log
        columns = ("path", "status", "rule", "quarantine")
        self.log_table = ttk.Treeview(
            log_card, columns=columns, show="headings", selectmode="browse"
        )

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=self.card_color,
            fieldbackground=self.card_color,
            foreground=self.text_primary,
            rowheight=24,
            borderwidth=0,
            relief="flat",
        )
        style.configure(
            "Treeview.Heading",
            background="#111827",
            foreground=self.text_primary,
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#374151")])

        self.log_table.heading("path", text="Path")
        self.log_table.heading("status", text="Status")
        self.log_table.heading("rule", text="Matched Rule(s)")
        self.log_table.heading("quarantine", text="Quarantined")

        self.log_table.column("path", width=450, anchor="w")
        self.log_table.column("status", width=100, anchor="center")
        self.log_table.column("rule", width=200, anchor="w")
        self.log_table.column("quarantine", width=100, anchor="center")

        self.log_table.pack(fill="both", expand=True, padx=10, pady=(5, 10))

    def _stat_chip(self, parent, title, value):
        frame = tk.Frame(parent, bg=self.card_color)
        frame.pack(side="left", padx=10)

        label_title = tk.Label(
            frame,
            text=title,
            bg=self.card_color,
            fg=self.text_muted,
            font=("Segoe UI", 9),
        )
        label_title.pack(anchor="w")

        label_value = tk.Label(
            frame,
            text=value,
            bg=self.card_color,
            fg=self.accent,
            font=("Segoe UI", 14, "bold"),
        )
        label_value.pack(anchor="w")
        return label_value

    # =============== RULE LOADING & EDITING ===============

    def _auto_load_rules(self):
        if os.path.exists(self.rules_path):
            try:
                self.rules = yara.compile(filepath=self.rules_path)
                self.status_label.config(text="Status: Ready (rules loaded)")
                self.rules_label.config(text=f"Rules file: {self.rules_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load default rules:\n{e}")

    def load_rules_dialog(self):
        path = filedialog.askopenfilename(
            title="Select YARA rules file",
            filetypes=[("YARA files", "*.yara *.yar"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            rules = yara.compile(filepath=path)
            self.rules = rules
            self.rules_path = path
            self.status_label.config(text="Status: Ready (rules loaded)")
            self.rules_label.config(text=f"Rules file: {self.rules_path}")
            messagebox.showinfo("Success", f"Rules loaded from:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load YARA rules:\n{e}")

    def edit_rules(self):
        if not os.path.exists(self.rules_path):
            messagebox.showwarning(
                "Warning", "No rules file found. Create 'malware_rules.yara' first."
            )
            return

        editor = tk.Toplevel(self)
        editor.title("Edit YARA Rules")
        editor.geometry("700x500")
        editor.config(bg=self.bg_color)

        text = tk.Text(
            editor,
            font=("Consolas", 10),
            bg="#020617",
            fg=self.text_primary,
            insertbackground="white",
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)

        with open(self.rules_path, "r", encoding="utf-8") as f:
            text.insert("1.0", f.read())

        def save_rules():
            content = text.get("1.0", "end-1c")
            try:
                # validate before saving
                temp_path = "_temp_rules.yara"
                with open(temp_path, "w", encoding="utf-8") as tmp:
                    tmp.write(content)
                yara.compile(filepath=temp_path)  # will raise if invalid
                os.remove(temp_path)

                with open(self.rules_path, "w", encoding="utf-8") as f:
                    f.write(content)

                self.rules = yara.compile(filepath=self.rules_path)
                self.status_label.config(text="Status: Ready (rules updated)")
                messagebox.showinfo("Success", "Rules saved & reloaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid YARA syntax:\n{e}")

        save_btn = tk.Button(
            editor,
            text="💾 Save & Reload",
            command=save_rules,
            bg=self.accent,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            bd=0,
            padx=10,
            pady=5,
        )
        save_btn.pack(pady=(0, 10))

    # =============== SCANNING LOGIC ===============

    def scan_file_dialog(self):
        if self.rules is None:
            messagebox.showwarning("Warning", "Load YARA rules first.")
            return

        path = filedialog.askopenfilename(title="Select file to scan")
        if not path:
            return

        self._scan_single_file(path)

    def scan_folder_dialog(self):
        if self.rules is None:
            messagebox.showwarning("Warning", "Load YARA rules first.")
            return

        folder = filedialog.askdirectory(title="Select folder to scan")
        if not folder:
            return

        # Use thread to avoid freezing GUI
        threading.Thread(target=self._scan_folder, args=(folder,), daemon=True).start()

    def _scan_single_file(self, path):
        self.status_label.config(
            text=f"Status: Scanning file: {os.path.basename(path)}"
        )
        self.update_idletasks()

        result = self._scan_path_with_yara(path)

        self._update_stats(result["status"])
        self._append_log(result)
        self._write_to_csv(result)

        # Popup
        if result["status"] == "Malicious":
            messagebox.showwarning(
                "Malware Detected",
                f"File: {path}\n\nMatched rule(s): {result['rules']}\n\nMoved to quarantine: {result['quarantined']}",
            )
        else:
            messagebox.showinfo("Scan Result", f"File is clean.\n\nPath: {path}")

        self.status_label.config(text="Status: Ready")

    def _scan_folder(self, folder):
        self.status_label.config(text=f"Status: Scanning folder: {folder}")
        self.update_idletasks()

        for root, _, files in os.walk(folder):
            for name in files:
                path = os.path.join(root, name)
                result = self._scan_path_with_yara(path)
                self._update_stats(result["status"])
                self._append_log(result)
                self._write_to_csv(result)
        self.status_label.config(text="Status: Ready (folder scan completed)")
        messagebox.showinfo("Completed", "Folder scan completed.")

    def _scheduled_scan_worker(self):
        """Background loop that periodically scans the selected folder."""
        while not self.sched_stop_event.is_set():
            if self.sched_folder and os.path.isdir(self.sched_folder):
                # reuse existing folder scan logic
                self._scan_folder(self.sched_folder)
            else:
                # invalid / deleted folder
                self.status_label.config(text="Status: Scheduled scan folder not found")

            # sleep for interval (in seconds), but check stop flag each second
            total_seconds = max(self.sched_interval, 1) * 60
            for _ in range(total_seconds):
                if self.sched_stop_event.is_set():
                    break
                time.sleep(1)

    def _scan_path_with_yara(self, path):
        status = "Clean"
        matched_rules = []
        quarantined = "No"

        try:
            matches = self.rules.match(filepath=path)
            if matches:
                status = "Malicious"
                matched_rules = [m.rule for m in matches]
                # Quarantine
                quarantined = self._quarantine_file(path)
        except Exception as e:
            status = f"Error: {e}"

        return {
            "path": path,
            "status": status,
            "rules": ", ".join(matched_rules) if matched_rules else "-",
            "quarantined": quarantined,
        }

    def _quarantine_file(self, path):
        try:
            base = os.path.basename(path)
            dest = os.path.join(QUARANTINE_DIR, base)
            # Avoid overwriting
            if os.path.exists(dest):
                name, ext = os.path.splitext(base)
                dest = os.path.join(QUARANTINE_DIR, f"{name}_{int(time.time())}{ext}")
            shutil.move(path, dest)
            return "Yes"
        except Exception:
            return "Failed"

    # =============== LOG & STATS ===============

    def _update_stats(self, status):
        self.total_scanned += 1
        if status.startswith("Error"):
            # don't count as clean/malicious
            pass
        elif status == "Malicious":
            self.total_malicious += 1
        else:
            self.total_clean += 1

        self.total_label.config(text=str(self.total_scanned))
        self.clean_label.config(text=str(self.total_clean))
        self.mal_label.config(text=str(self.total_malicious))

    def _append_log(self, result):
        self.log_table.insert(
            "",
            "end",
            values=(
                result["path"],
                result["status"],
                result["rules"],
                result["quarantined"],
            ),
        )
        # Auto-scroll
        self.log_table.yview_moveto(1)

    def _write_to_csv(self, result):
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    result["path"],
                    result["status"],
                    result["rules"],
                    result["quarantined"],
                ]
            )

    # =============== OTHER FEATURES ===============

    def open_quarantine_folder(self):
        path = os.path.abspath(QUARANTINE_DIR)
        if os.name == "nt":
            os.startfile(path)
        elif os.name == "posix":
            os.system(f'xdg-open "{path}"')
        else:
            messagebox.showinfo("Quarantine", f"Quarantine folder: {path}")

    def schedule_scan_basic(self):
        """Open a window to configure a delayed repeating folder scan."""
        if self.rules is None:
            messagebox.showwarning("Warning", "Load YARA rules first.")
            return

        win = tk.Toplevel(self)
        win.title("Basic Schedule Scan")
        win.geometry("400x200")
        win.configure(bg=self.bg_color)

        # ---- Folder selection ----
        tk.Label(
            win,
            text="Folder to scan:",
            bg=self.bg_color,
            fg=self.text_primary,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=10, pady=(10, 0))

        folder_var = tk.StringVar(value=self.sched_folder or "")

        entry_folder = tk.Entry(
            win,
            textvariable=folder_var,
            bg="#020617",
            fg=self.text_primary,
            insertbackground="white",
        )
        entry_folder.pack(fill="x", padx=10, pady=(0, 5))

        def browse_folder():
            path = filedialog.askdirectory(title="Select folder to schedule scan")
            if path:
                folder_var.set(path)

        tk.Button(
            win,
            text="Browse",
            command=browse_folder,
            bg=self.accent,
            fg="white",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        ).pack(anchor="e", padx=10, pady=(0, 10))

        # ---- Interval selection ----
        tk.Label(
            win,
            text="Interval (minutes):",
            bg=self.bg_color,
            fg=self.text_primary,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=10)

        interval_var = tk.IntVar(value=self.sched_interval or 5)

        tk.Spinbox(
            win,
            from_=1,
            to=1440,
            textvariable=interval_var,
            bg="#020617",
            fg=self.text_primary,
            insertbackground="white",
            width=6,
        ).pack(anchor="w", padx=10, pady=(0, 10))

        # ---- Start / Stop buttons ----
        btn_frame = tk.Frame(win, bg=self.bg_color)
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        def start_schedule():
            folder = folder_var.get().strip()
            if not folder or not os.path.isdir(folder):
                messagebox.showwarning("Warning", "Please select a valid folder.")
                return

            self.sched_folder = folder
            self.sched_interval = int(interval_var.get())
            self.sched_stop_event.clear()

            if not self.sched_thread or not self.sched_thread.is_alive():
                self.sched_thread = threading.Thread(
                    target=self._scheduled_scan_worker, daemon=True
                )
                self.sched_thread.start()

            self.status_label.config(
                text=f"Status: Scheduled scan set (starts in {self.sched_interval} min)"
            )

            messagebox.showinfo(
                "Scheduled",
                f"Folder:\n{folder}\n\nFirst scan will run after {self.sched_interval} minute(s).",
            )
            win.destroy()

        def stop_schedule():
            self.sched_stop_event.set()
            self.status_label.config(text="Status: Scheduled scan stopped")
            messagebox.showinfo("Stopped", "Scheduled scanning stopped.")
            win.destroy()

        tk.Button(
            btn_frame,
            text="Start",
            command=start_schedule,
            bg=self.accent,
            fg="white",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
        ).pack(side="left")

        tk.Button(
            btn_frame,
            text="Stop",
            command=stop_schedule,
            bg="#6b7280",
            fg="white",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
        ).pack(side="right")

    def _scheduled_scan_worker(self):
        """
        Background scheduler:
        waits for the given interval,
        then scans the folder,
        repeats until stopped.
        """

        while not self.sched_stop_event.is_set():

            # 1️⃣ Wait FIRST for interval time
            total_seconds = max(self.sched_interval, 1) * 60
            for _ in range(total_seconds):
                if self.sched_stop_event.is_set():
                    return
                time.sleep(1)

            # 2️⃣ Scan AFTER waiting
            if self.sched_folder and os.path.isdir(self.sched_folder):
                self.status_label.config(
                    text=f"Status: Scheduled scan running (every {self.sched_interval} min)"
                )
                self._scan_folder(self.sched_folder)
            else:
                self.status_label.config(text="Status: Scheduled scan folder not found")

    def open_project_info_in_ui(self):
        """Open the PROJECT_PDF inside a Toplevel using PyMuPDF-rendered images."""

        if not os.path.exists(PROJECT_PDF):
            messagebox.showerror("Error", f"PDF not found:\n{PROJECT_PDF}")
            return

        # Try to import render libs; fallback to external opener if unavailable
        try:
            import fitz
            from PIL import Image, ImageTk
        except Exception as e:
            # fallback: open in system default app
            try:
                if os.name == "nt":
                    os.startfile(PROJECT_PDF)
                elif sys.platform == "darwin":
                    os.system(f'open "{PROJECT_PDF}"')
                else:
                    os.system(f'xdg-open "{PROJECT_PDF}"')
            except:
                messagebox.showerror(
                    "Error",
                    "Cannot display PDF internally and failed to open externally.",
                )
            return

        # Load document
        try:
            doc = fitz.open(PROJECT_PDF)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open PDF:\n{e}")
            return

        # Create viewer window
        viewer = tk.Toplevel(self)
        viewer.title("Project Info — PDF Viewer")
        viewer.geometry("900x900")
        viewer.configure(bg=self.bg_color)

        # State for current page
        state = {"page_index": 0, "page_imgs": [None] * len(doc)}

        # Canvas to show page image
        canvas_frame = tk.Frame(viewer, bg=self.bg_color)
        canvas_frame.pack(fill="both", expand=True, padx=8, pady=8)
        canvas = tk.Canvas(canvas_frame, bg=self.card_color)
        canvas.pack(fill="both", expand=True)

        # Footer with controls
        footer = tk.Frame(viewer, bg=self.card_color)
        footer.pack(fill="x", padx=8, pady=(0, 8))

        page_label = tk.Label(
            footer,
            text=f"Page 1 / {len(doc)}",
            bg=self.card_color,
            fg=self.text_primary,
        )
        page_label.pack(side="left", padx=8)

        def render_page_to_photo(page_num, max_width=1200, max_height=900):
            """Render page to PhotoImage (cached)."""
            if state["page_imgs"][page_num] is not None:
                return state["page_imgs"][page_num]

            page = doc.load_page(page_num)
            # render at 150 dpi scale (tweak if needed)
            zoom_x = 2.0  # 2.0 ~ 144 dpi; adjust if small/large
            zoom_y = 2.0
            mat = fitz.Matrix(zoom_x, zoom_y)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img_data = pix.tobytes("png")
            pil_img = Image.open(io.BytesIO(img_data))
            # optional resizing to fit window
            w, h = pil_img.size
            ratio = min(max_width / w, max_height / h, 1.0)
            if ratio < 1.0:
                pil_img = pil_img.resize(
                    (int(w * ratio), int(h * ratio)), Image.LANCZOS
                )
            photo = ImageTk.PhotoImage(pil_img)
            state["page_imgs"][page_num] = photo
            return photo

        def show_page(idx):
            canvas.delete("all")
            try:
                photo = render_page_to_photo(
                    idx,
                    max_width=viewer.winfo_width() - 40,
                    max_height=viewer.winfo_height() - 140,
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to render page {idx+1}:\n{e}")
                return
            # center image on canvas
            canvas_img = canvas.create_image(0, 0, anchor="nw", image=photo)
            canvas.photo = photo  # keep reference
            canvas.config(scrollregion=canvas.bbox("all"))
            page_label.config(text=f"Page {idx+1} / {len(doc)}")

        def on_prev():
            if state["page_index"] > 0:
                state["page_index"] -= 1
                show_page(state["page_index"])

        def on_next():
            if state["page_index"] < len(doc) - 1:
                state["page_index"] += 1
                show_page(state["page_index"])

        btn_prev = tk.Button(
            footer,
            text="◀ Prev",
            command=on_prev,
            bg=self.accent,
            fg="white",
            bd=0,
            padx=8,
            pady=4,
        )
        btn_prev.pack(side="right", padx=(0, 6))
        btn_next = tk.Button(
            footer,
            text="Next ▶",
            command=on_next,
            bg=self.accent,
            fg="white",
            bd=0,
            padx=8,
            pady=4,
        )
        btn_next.pack(side="right")

        # initial render
        viewer.update_idletasks()
        show_page(0)

        # cleanup when window closed
        def on_close():
            try:
                doc.close()
            except:
                pass
            viewer.destroy()

        viewer.protocol("WM_DELETE_WINDOW", on_close)


if __name__ == "__main__":
    app = MalwareScannerApp()
    app.mainloop()
