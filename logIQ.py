import customtkinter
from tkinter import ttk
import re
import json
import base64
import io
import ipaddress
import threading
from collections import Counter
from datetime import datetime

import requests
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Configure global theme settings
customtkinter.set_appearance_mode("Dark") # System, light and Dark
customtkinter.set_default_color_theme("blue")

APP_NAME = "LogIQ"

HIGH_RISK_COUNTRIES = {"China", "Russia", "North Korea", "Iran"}

PORT_NAMES = {
    "20": "FTP-DATA", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS",
    "445": "SMB", "993": "IMAPS", "995": "POP3S", "1433": "MSSQL",
    "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
    "6379": "Redis", "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "27017": "MongoDB",
}

# (log type name, list of keyword patterns used to fingerprint it)
LOG_TYPE_SIGNATURES = {
    "Linux SSH": ["Accepted password", "Failed password", "Invalid user", "sshd"],
    "Apache/Nginx Access": [r"\"(GET|POST|PUT|DELETE|HEAD)\s", "HTTP/1.1\"", "HTTP/1.0\""],
    "Windows Event Log": ["EventID", "Microsoft-Windows", "Logon Type"],
    "Linux Firewall (iptables)": ["IN=", "OUT=", "SRC=", "DPT="],
}

# Timestamp patterns tried in order; each must have exactly two capturing
# groups: (hour, minute). We pick whichever pattern gets the most matches.
TIMESTAMP_PATTERNS = [
    r"\b\w{3}\s+\d{1,2}\s(\d{2}):(\d{2}):\d{2}\b",              # syslog: "Jul  5 03:15:22"
    r"\b\d{4}-\d{2}-\d{2}[ T](\d{2}):(\d{2}):\d{2}\b",           # ISO: "2026-07-05T03:15:22"
    r"\[\d{2}/\w{3}/\d{4}:(\d{2}):(\d{2}):\d{2}",                # Apache: "[05/Jul/2026:03:15:22"
]

IP_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

#
def is_private_ip(ip: str) -> bool:
    """Return True if the IP is private/reserved and shouldn't be geolocated."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True


class LogAnalyzerApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("980x720")
        self.minsize(860, 620)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- Analysis state (populited after a file is loaded) ----
        self.log_data = ""
        self.ip_counts = {}
        self.country_counts = Counter()
        self.port_counts = Counter()
        self.timeline_counts = Counter()
        self.username_counts = Counter()
        self.detection = {"type": "Unknown", "confidence": 0, "found": [], "missing": []}
        self.first_seen = None
        self.last_seen = None
        self.threat_score = "LOW"
        self.pie_figure = None

        # ---- Top bar ----
        self.browse_btn = customtkinter.CTkButton(
            self, text="Browse Log File", command=self.browse_file
        )
        self.browse_btn.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        self.path_label = customtkinter.CTkLabel(
            self, text="No file selected", font=("Arial", 12, "italic")
        )
        self.path_label.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # ---- tabs ---
        self.tabs = customtkinter.CTkTabview(self)
        self.tabs.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.tab_overview = self.tabs.add("Overview")
        self.tab_countries = self.tabs.add("Countries")
        self.tab_report = self.tabs.add("Report")

        self._build_overview_tab()
        self._build_countries_tab()
        self._build_report_tab()

    # ------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------
    def _build_overview_tab(self):
        self.tab_overview.grid_columnconfigure(0, weight=1)
        self.tab_overview.grid_columnconfigure(1, weight=1)

        scroll = customtkinter.CTkScrollableFrame(self.tab_overview)
        scroll.pack(fill="both", expand=True)
        scroll.grid_columnconfigure(0, weight=1)
        scroll.grid_columnconfigure(1, weight=1)

        # --- Detection panel ---
        detect_frame = customtkinter.CTkFrame(scroll)
        detect_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        customtkinter.CTkLabel(
            detect_frame, text="Log Type Detection", font=("Arial", 14, "bold")
        ).pack(anchor="w", padx=10, pady=(10, 0))
        self.detection_box = customtkinter.CTkTextbox(detect_frame, height=110, font=("Consolas", 12))
        self.detection_box.pack(fill="x", expand=True, padx=10, pady=10)
        self.detection_box.insert("0.0", "Load a log file to detect its type...")
        self.detection_box.configure(state="disabled")

        # --- Attack summary panel ---
        summary_frame = customtkinter.CTkFrame(scroll)
        summary_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        customtkinter.CTkLabel(
            summary_frame, text="Attack Summary", font=("Arial", 14, "bold")
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 5))

        self.summary_labels = {}
        summary_fields = [
            "Log Type", "Most Targeted User", "Most Common IP",
            "Countries", "First Seen", "Last Seen", "Threat Score",
        ]
        for i, field in enumerate(summary_fields, start=1):
            customtkinter.CTkLabel(
                summary_frame, text=f"{field}:", font=("Arial", 12, "bold")
            ).grid(row=i, column=0, sticky="w", padx=10, pady=3)
            value_label = customtkinter.CTkLabel(summary_frame, text="—", font=("Arial", 12))
            value_label.grid(row=i, column=1, sticky="w", padx=10, pady=3)
            self.summary_labels[field] = value_label

        # --- Ports panel ---
        ports_frame = customtkinter.CTkFrame(scroll)
        ports_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
        customtkinter.CTkLabel(
            ports_frame, text="Ports Observed", font=("Arial", 14, "bold")
        ).pack(anchor="w", padx=10, pady=(10, 0))
        self.ports_box = customtkinter.CTkTextbox(ports_frame, height=170, font=("Consolas", 12))
        self.ports_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.ports_box.insert("0.0", "No data yet.")
        self.ports_box.configure(state="disabled")

        # --- Top IPs table ---
        ips_frame = customtkinter.CTkFrame(
            scroll,
            fg_color="#1f1f1f"
        )
        ips_frame.grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="nsew",
            padx=10,
            pady=10
        )

        customtkinter.CTkLabel(
            ips_frame,
            text="Top IPs",
            font=("Arial", 14, "bold"),
            text_color="white",
            fg_color="transparent"
        ).pack(anchor="w", padx=10, pady=(10, 5))

        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "LogIQ.Treeview",
            background="#1f1f1f",
            foreground="white",
            fieldbackground="#1f1f1f",
            rowheight=26,
            font=("Arial", 11),
            borderwidth=0
        )

        style.configure(
            "LogIQ.Treeview.Heading",
            background="#1f1f1f",
            foreground="white",
            font=("Arial", 11, "bold"),
            relief="flat"
        )

        style.map(
            "LogIQ.Treeview",
            background=[("selected", "#2563EB")],
            foreground=[("selected", "white")]
        )

        style.map(
            "LogIQ.Treeview.Heading",
            background=[("active", "#2d2d2d")]
        )
        self.ip_tree = ttk.Treeview(
            ips_frame, columns=("ip", "attempts", "country", "risk"),
            show="headings", height=8, style="LogIQ.Treeview"
        )
        for col, label, width in [
            ("ip", "IP", 160), ("attempts", "Attempts", 90),
            ("country", "Country", 160), ("risk", "Risk", 90),
        ]:
            self.ip_tree.heading(col, text=label)
            self.ip_tree.column(col, width=width, anchor="center")
        self.ip_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ip_tree.tag_configure("High", foreground="#e33")
        self.ip_tree.tag_configure("Medium", foreground="#d90")
        self.ip_tree.tag_configure("Low", foreground="#2a2")

        # --- Timeline panel ---
        timeline_frame = customtkinter.CTkFrame(scroll)
        timeline_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        customtkinter.CTkLabel(
            timeline_frame, text="Timeline (attempts per hour)", font=("Arial", 14, "bold")
        ).pack(anchor="w", padx=10, pady=(10, 0))
        self.timeline_box = customtkinter.CTkTextbox(timeline_frame, height=260, font=("Consolas", 12))
        self.timeline_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.timeline_box.insert("0.0", "No data yet.")
        self.timeline_box.configure(state="disabled")

    def _build_countries_tab(self):
        self.tab_countries.grid_columnconfigure(0, weight=1)
        self.tab_countries.grid_rowconfigure(1, weight=1)

        self.chart_btn = customtkinter.CTkButton(
            self.tab_countries, text="Generate Country Chart",
            command=self.show_country_chart, state="disabled"
        )
        self.chart_btn.grid(row=0, column=0, pady=10)

        self.chart_container = customtkinter.CTkFrame(self.tab_countries, fg_color="transparent")
        self.chart_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        self.chart_placeholder = customtkinter.CTkLabel(
            self.chart_container, text="Load a log file and click \"Generate Country Chart\".",
            font=("Arial", 13, "italic")
        )
        self.chart_placeholder.pack(expand=True)

    def _build_report_tab(self):
        customtkinter.CTkLabel(
            self.tab_report, text="Export Report", font=("Arial", 16, "bold")
        ).pack(pady=(20, 10))
        customtkinter.CTkLabel(
            self.tab_report,
            text="Generate a shareable report of this analysis.",
            font=("Arial", 12)
        ).pack(pady=(0, 20))

        btn_frame = customtkinter.CTkFrame(self.tab_report, fg_color="transparent")
        btn_frame.pack(pady=10.)

        self.report_buttons = []
        for label, command in [
            ("Export HTML", self.export_html),
            ("Export JSON", self.export_json),
            ("Export PDF", self.export_pdf),
        ]:
            btn = customtkinter.CTkButton(btn_frame, text=label, command=command, state="disabled", width=160)
            btn.pack(side="left", padx=10)
            self.report_buttons.append(btn)

        self.report_status = customtkinter.CTkLabel(self.tab_report, text="", font=("Arial", 12))
        self.report_status.pack(pady=15)

    # ------------------------------------------------------------------
    # File loading \ analysis pipeline
    # ------------------------------------------------------------------
    def browse_file(self):
        file_path = customtkinter.filedialog.askopenfilename(
            title="Select a Log File",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        self.path_label.configure(text=f"Selected: {file_path}", font=("Arial", 12, "normal"))
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                log_data = file.read()
        except Exception as e:
            self._set_textbox(self.detection_box, f"Error reading file: {str(e)}")
            return

        self.log_data = log_data
        self.analyze_log(log_data)

    def analyze_log(self, log_data: str):
        # --- IP extraction ---
        matches = re.findall(IP_PATTERN, log_data)
        self.ip_counts = dict(Counter(matches))

        # --- Log type detection ---
        self.detection = self._detect_log_type(log_data)
        self._render_detection()

        # --- Ports ---
        self.port_counts = self._extract_ports(log_data)
        self._render_ports()

        # --- Timeline ---
        self.timeline_counts, self.first_seen, self.last_seen = self._extract_timeline(log_data)
        self._render_timeline()

        # --- Usernames ---
        self.username_counts = self._extract_usernames(log_data)

        # --- Threat score ---
        self.threat_score = self._compute_threat_score()

        # --- Top IPs table (country resolved lazily/async) ---
        self._render_top_ips(resolved_countries=None)

        # --- summary (partial; countries fill in after resolution) --- 
        self._render_summary(countries_text="Resolving...")

        # Reset countries tab
        self.country_counts = Counter()
        for widget in self.chart_container.winfo_children():
            widget.destroy()
        self.chart_placeholder = customtkinter.CTkLabel(
            self.chart_container, text="Click \"Generate Country Chart\" to resolve countries.",
            font=("Arial", 13, "italic")
        )
        self.chart_placeholder.pack(expand=True)
        #

        has_ips = bool(self.ip_counts)
        self.chart_btn.configure(state="normal" if has_ips else "disabled")
        for btn in self.report_buttons:
            btn.configure(state="normal" if has_ips else "disabled")

        # Kick off country resolution in the background so the summary/top-IP
        # table and report can show real country data without blocking the UI.
        if has_ips:
            threading.Thread(target=self._background_resolve_countries, daemon=True).start()

    # ------------------------------------------------------------------
    # Log type detection
    # ------------------------------------------------------------------
    def _detect_log_type(self, log_data: str):
        best_type, best_found, best_missing, best_ratio = "Unknown/Generic", [], [], 0.0
        for log_type, signatures in LOG_TYPE_SIGNATURES.items():
            found = [sig for sig in signatures if re.search(sig, log_data)]
            missing = [sig for sig in signatures if sig not in found]
            ratio = len(found) / len(signatures)
            if ratio > best_ratio:
                best_type, best_found, best_missing, best_ratio = log_type, found, missing, ratio

        if best_ratio == 0:
            return {"type": "Unknown/Generic", "confidence": 0, "found": [], "missing": []}

        confidence = round(best_ratio * 100)
        return {"type": best_type, "confidence": confidence, "found": best_found, "missing": best_missing}

    def _render_detection(self):
        d = self.detection
        lines = ["Detecting log type..."]
        if d["confidence"] > 0:
            lines.append(f"\u2713 {d['type']}")
            lines.append(f"Confidence: {d['confidence']}%")
            lines.append("Reason:")
            lines.append("Found:")
            for f in d["found"]:
                lines.append(f"  - {f}")
            if d["missing"]:
                lines.append("Not found:")
                for m in d["missing"]:
                    lines.append(f"  - {m}")
        else:
            lines.append("\u2717 Could not confidently identify log type")
            lines.append("This log doesn't match any known signature (SSH, web server, Windows, firewall).")
        self._set_textbox(self.detection_box, "\n".join(lines))

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------
    def _extract_ports(self, log_data: str) -> Counter:
        counts = Counter()
        counts.update(re.findall(r"DPT=(\d+)", log_data))
        counts.update(re.findall(r"\bport\s+(\d{1,5})\b", log_data, flags=re.IGNORECASE))
        return counts

    def _render_ports(self):
        if not self.port_counts:
            self._set_textbox(self.ports_box, "No port information found in this log format.")
            return
        port_numbers = [int(p) for p in self.port_counts.keys()]
        lowest, highest = min(port_numbers), max(port_numbers)
        lines = [f"Port Range: {lowest} - {highest}", ""]
        for port, count in self.port_counts.most_common():
            name = PORT_NAMES.get(port, "Unknown")
            lines.append(f"{port:>5}  -  {name:<10}  ({count} occurrences)")
        self._set_textbox(self.ports_box, "\n".join(lines))

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------
    def _extract_timeline(self, log_data: str):
        best_matches, best_count = [], 0
        for pattern in TIMESTAMP_PATTERNS:
            found = re.findall(pattern, log_data)
            if len(found) > best_count:
                best_matches, best_count = found, len(found)

        if not best_matches:
            return Counter(), None, None

        hours = Counter(hr for hr, _minute in best_matches)
        first_seen = f"{best_matches[0][0]}:{best_matches[0][1]}"
        last_seen = f"{best_matches[-1][0]}:{best_matches[-1][1]}"
        return hours, first_seen, last_seen

    def _render_timeline(self):
        if not self.timeline_counts:
            self._set_textbox(self.timeline_box, "No recognizable timestamps found in this log format.")
            return
        max_count = max(self.timeline_counts.values())
        scale = 40 / max_count if max_count > 0 else 1
        lines = []
        for hour in range(24):
            count = self.timeline_counts.get(f"{hour:02d}", 0)
            bar_len = round(count * scale)
            hour_label = datetime.strptime(f"{hour:02d}", "%H").strftime("%I%p").lstrip("0")
            bar = "\u2588" * bar_len
            lines.append(f"{hour_label:>4} {bar} {count}")
        self._set_textbox(self.timeline_box, "\n".join(lines))

    # ------------------------------------------------------------------
    # Usernames
    # ------------------------------------------------------------------
    def _extract_usernames(self, log_data: str) -> Counter:
        counts = Counter()
        counts.update(re.findall(r"for (?:invalid user )?(\w+) from", log_data))
        counts.update(re.findall(r"Invalid user (\w+) from", log_data))
        return counts

    # ------------------------------------------------------------------
    # Threat score
    # ------------------------------------------------------------------
    def _compute_threat_score(self) -> str:
        score = 0
        total_attempts = sum(self.ip_counts.values())
        unique_ips = len(self.ip_counts)

        if total_attempts >= 500:
            score += 3
        elif total_attempts >= 100:
            score += 2
        elif total_attempts >= 20:
            score += 1

        if unique_ips >= 30:
            score += 2
        elif unique_ips >= 10:
            score += 1

        if self.username_counts:
            top_user = self.username_counts.most_common(1)[0][0]
            if top_user.lower() == "root":
                score += 1

        if any(country in HIGH_RISK_COUNTRIES and count >= 5
               for country, count in self.country_counts.items()):
            score += 1

        if score >= 6:
            return "CRITICAL"
        elif score >= 4:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Top IPs table
    # ------------------------------------------------------------------
    def _classify_ip_risk(self, ip: str, attempts: int, country: str) -> str:
        if is_private_ip(ip):
            return "Low"
        if country in HIGH_RISK_COUNTRIES and attempts >= 5:
            return "High"
        if attempts >= 30:
            return "High"
        if attempts >= 10:
            return "Medium"
        return "Low"

    def _render_top_ips(self, resolved_countries):
        for row in self.ip_tree.get_children():
            self.ip_tree.delete(row)

        top_ips = sorted(self.ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
        for ip, attempts in top_ips:
            if resolved_countries is not None:
                country = resolved_countries.get(ip, "Unknown")
            else:
                country = "Local" if is_private_ip(ip) else "Resolving..."
            risk = self._classify_ip_risk(ip, attempts, country)
            self.ip_tree.insert("", "end", values=(ip, attempts, country, risk), tags=(risk,))

    # ------------------------------------------------------------------
    # Summary panel
    # ------------------------------------------------------------------
    def _render_summary(self, countries_text: str):
        most_common_ip = "—"
        if self.ip_counts:
            most_common_ip = max(self.ip_counts.items(), key=lambda kv: kv[1])[0]

        most_targeted_user = "—"
        if self.username_counts:
            most_targeted_user = self.username_counts.most_common(1)[0][0]

        values = {
            "Log Type": self.detection["type"],
            "Most Targeted User": most_targeted_user,
            "Most Common IP": most_common_ip,
            "Countries": countries_text,
            "First Seen": self.first_seen or "—",
            "Last Seen": self.last_seen or "—",
            "Threat Score": self.threat_score,
        }
        for field, value in values.items():
            self.summary_labels[field].configure(text=str(value))

        threat_colors = {"LOW": "#2a2", "MEDIUM": "#d90", "HIGH": "#e60", "CRITICAL": "#e33"}
        self.summary_labels["Threat Score"].configure(
            text_color=threat_colors.get(self.threat_score, "white")
        )

    # ------------------------------------------------------------------
    # Country resolution  + pie chart
    # ------------------------------------------------------------------
    def _background_resolve_countries(self):
        try:
            country_map, country_counts = self._resolve_countries(self.ip_counts)
            error = None
        except Exception as e:
            country_map, country_counts, error = {}, Counter(), str(e)
        self.after(0, lambda: self._on_countries_resolved(country_map, country_counts, error))
        """I wish ipwhois worked for shit"""
    def _resolve_countries(self, ip_counts: dict):
        """ each unique IP to a country via ip-api.com's free batch endpoint"""
        country_map = {}
        country_counts = Counter()
        ips_to_query = []

        for ip in ip_counts:
            if is_private_ip(ip):
                country_map[ip] = "Local"
                country_counts["Private/Local"] += ip_counts[ip]
            else:
                ips_to_query.append(ip)

        batch_size = 100
        for i in range(0, len(ips_to_query), batch_size):
            batch = ips_to_query[i:i + batch_size]
            payload = [{"query": ip, "fields": "status,country,query"} for ip in batch]
            response = requests.post("http://ip-api.com/batch", json=payload, timeout=10)
            response.raise_for_status()
            for result in response.json():
                ip = result.get("query")
                country = result.get("country", "Unknown") if result.get("status") == "success" else "Unknown"
                country_map[ip] = country
                country_counts[country] += ip_counts.get(ip, 0)

        return country_map, country_counts

    def _on_countries_resolved(self, country_map, country_counts, error):
        if error is not None:
            self._render_summary(countries_text="Lookup failed")
            self.report_status.configure(text=f"Country lookup failed: {error}", text_color="#e33")
            return

        self.country_counts = country_counts
        self._render_top_ips(resolved_countries=country_map)

        top_countries = [c for c, _ in country_counts.most_common(3)]
        self._render_summary(countries_text=", ".join(top_countries) if top_countries else "—")

        # Threat score can change once real country data is in (high-risk country rule) because it is decided based off of that
        self.threat_score = self._compute_threat_score()
        self._render_summary(countries_text=", ".join(top_countries) if top_countries else "—")

    def show_country_chart(self):
        if not self.ip_counts:
            return
        self.chart_btn.configure(state="disabled", text="Loading countries...")
        threading.Thread(target=self._generate_chart_thread, daemon=True).start()

    def _generate_chart_thread(self):
        if not self.country_counts:
            try:
                _, country_counts = self._resolve_countries(self.ip_counts)
                error = None
            except Exception as e:
                country_counts, error = Counter(), str(e)
            self.country_counts = country_counts
        else:
            error = None
        self.after(0, lambda: self._render_chart(error))

    def _render_chart(self, error):
        self.chart_btn.configure(state="normal", text="Generate Country Chart")
        for widget in self.chart_container.winfo_children():
            widget.destroy()

        if error is not None:
            customtkinter.CTkLabel(
                self.chart_container, text=f"Could not resolve countries: {error}",
                font=("Arial", 13)
            ).pack(expand=True)
            return

        if not self.country_counts:
            customtkinter.CTkLabel(
                self.chart_container, text="No country data available.", font=("Arial", 13)
            ).pack(expand=True)
            return

        fig = self._build_pie_figure(self.country_counts)
        self.pie_figure = fig
        canvas = FigureCanvasTkAgg(fig, master=self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _build_pie_figure(self, country_counts: Counter, other_threshold: float = 0.02):

        total = sum(country_counts.values())
        grouped = Counter()
        other_total = 0
        for country, count in country_counts.items():
            if total > 0 and (count / total) < other_threshold:
                other_total += count
            else:
                grouped[country] = count
        if other_total:
            grouped["Other"] = other_total

        sorted_items = grouped.most_common()
        labels = [c for c, _ in sorted_items]
        sizes = [n for _, n in sorted_items]

        fig, ax = plt.subplots(figsize=(7, 5.5))
        wedges, _texts, _autotexts = ax.pie(
            sizes,
            autopct=lambda pct: f"{pct:.1f}%" if pct >= 3 else "",
            startangle=90,
            pctdistance=0.8,
        )
        ax.axis("equal")
        ax.set_title("Log Entries by Country")
        ax.legend(
            wedges, [f"{l} ({n})" for l, n in zip(labels, sizes)],
            title="Country", loc="center left", bbox_to_anchor=(1.02, 0.5),
            fontsize=9, frameon=False
        )
        fig.tight_layout()
        return fig

    # ------------------------------------------------------------------
    # Report export
    # ------------------------------------------------------------------
    def _build_report_data(self) -> dict:
        top_ips = []
        for ip, attempts in sorted(self.ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]:
            country = "Local" if is_private_ip(ip) else self._country_for_ip(ip)
            top_ips.append({
                "ip": ip, "attempts": attempts, "country": country,
                "risk": self._classify_ip_risk(ip, attempts, country),
            })

        most_common_ip = max(self.ip_counts.items(), key=lambda kv: kv[1])[0] if self.ip_counts else None
        most_targeted_user = self.username_counts.most_common(1)[0][0] if self.username_counts else None

        return {
            "app": APP_NAME,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "log_type": self.detection["type"], 
            "detection_confidence": self.detection["confidence"],
            "threat_score": self.threat_score,
            "most_targeted_user": most_targeted_user,
            "most_common_ip": most_common_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_attempts": sum(self.ip_counts.values()),
            "unique_ips": len(self.ip_counts),
            "top_ips": top_ips,
            "countries": dict(self.country_counts.most_common()),
            "ports": {p: {"name": PORT_NAMES.get(p, "Unknown"), "count": c}
                      for p, c in self.port_counts.most_common()},
            "port_range": (
                {"lowest": min(int(p) for p in self.port_counts), "highest": max(int(p) for p in self.port_counts)}
                if self.port_counts else None
            ),
            "timeline_by_hour": {h: self.timeline_counts.get(f"{h:02d}", 0) for h in range(24)},
        }

    def _country_for_ip(self, ip: str) -> str:
        for row_id in self.ip_tree.get_children():
            values = self.ip_tree.item(row_id, "values")
            if values and values[0] == ip:
                return values[2]
        return "Unknown"

    def export_json(self):
        path = customtkinter.filedialog.asksaveasfilename(
            title="Save JSON Report", defaultextension=".json",
            filetypes=[("JSON File", "*.json")]
        )
        if not path:
            return
        data = self._build_report_data()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.report_status.configure(text=f"JSON report saved to {path}", text_color="#2a2")
        except Exception as e:
            self.report_status.configure(text=f"Failed to save JSON: {e}", text_color="#e33")

    def export_html(self):
        path = customtkinter.filedialog.asksaveasfilename(
            title="Save HTML Report", defaultextension=".html",
            filetypes=[("HTML File", "*.html")]
        )
        if not path:
            return
        data = self._build_report_data()

        chart_img_tag = ""
        if self.country_counts:
            fig = self._build_pie_figure(self.country_counts)
            buf = io.BytesIO()
            fig.savefig(buf, format="png", bbox_inches="tight", dpi=120)
            plt.close(fig)
            encoded = base64.b64encode(buf.getvalue()).decode("ascii")
            chart_img_tag = f'<img src="data:image/png;base64,{encoded}" style="max-width:100%;">'

        rows = "".join(
            f"<tr><td>{ip['ip']}</td><td>{ip['attempts']}</td>"
            f"<td>{ip['country']}</td><td class='risk-{ip['risk'].lower()}'>{ip['risk']}</td></tr>"
            for ip in data["top_ips"]
        )
        port_rows = "".join(
            f"<tr><td>{p}</td><td>{info['name']}</td><td>{info['count']}</td></tr>"
            for p, info in data["ports"].items()
        ) or "<tr><td colspan='3'>No port data found.</td></tr>"

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{APP_NAME} Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
h1 {{ color: #1f6aa5; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: center; }}
th {{ background: #1f6aa5; color: white; }}
.risk-high {{ color: #c0392b; font-weight: bold; }}
.risk-medium {{ color: #d68910; font-weight: bold; }}
.risk-low {{ color: #27ae60; font-weight: bold; }}
.summary-grid {{ display: grid; grid-template-columns: 200px 1fr; gap: 6px; max-width: 600px; }}
</style>
</head>
<body>
<h1>{APP_NAME} Attack Report</h1>
<p>Generated: {data['generated_at']}</p>

<h2>Attack Summary</h2>
<div class="summary-grid">
<b>Log Type:</b><span>{data['log_type']}  ({data['detection_confidence']}% confidence)</span>
<b>Threat Score:</b><span>{data['threat_score']}</span>
<b>Most Targeted User:</b><span>{data['most_targeted_user'] or '—'}</span>
<b>Most Common IP:</b><span>{data['most_common_ip'] or '—'}</span>
<b>First Seen:</b><span>{data['first_seen'] or '—'}</span>
<b>Last Seen:</b><span>{data['last_seen'] or '—'}</span>
<b>Total Attempts:</b><span>{data['total_attempts']}</span>
<b>Unique IPs:</b><span>{data['unique_ips']}</span>
</div>

<h2>Countries</h2>
{chart_img_tag}

<h2>Top IPs</h2>
<table>
<tr><th>IP</th><th>Attempts</th><th>Country</th><th>Risk</th></tr>
{rows}
</table>

<h2>Ports Observed</h2>
{f"<p><b>Port Range:</b> {data['port_range']['lowest']} - {data['port_range']['highest']}</p>" if data['port_range'] else ""}
<table>
<tr><th>Port</th><th>Service</th><th>Occurrences</th></tr>
{port_rows}
</table>

</body>
</html>"""
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            self.report_status.configure(text=f"HTML report saved to {path}", text_color="#2a2")
        except Exception as e:
            self.report_status.configure(text=f"Failed to save HTML: {e}", text_color="#e33")

    def export_pdf(self):
        try:
            from fpdf import FPDF
        except ImportError:
            self.report_status.configure(
                text="PDF export requires the 'fpdf2' package. Install it with: pip install fpdf2",
                text_color="#e33"
            )
            return

        path = customtkinter.filedialog.asksaveasfilename(
            title="Save PDF Report", defaultextension=".pdf",
            filetypes=[("PDF File", "*.pdf")]
        )
        if not path:
            return

        def s(text):
            """Sanitize text to the Latin-1 subset the built-in PDF fonts support."""
            return str(text).encode("latin-1", "replace").decode("latin-1")

        data = self._build_report_data()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, s(f"{APP_NAME} Attack Report"), ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, s(f"Generated: {data['generated_at']}"), ln=True)
        pdf.ln(4)

        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Attack Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for label, value in [
            ("Log Type", f"{data['log_type']} ({data['detection_confidence']}% confidence)"),
            ("Threat Score", data["threat_score"]),
            ("Most Targeted User", data["most_targeted_user"] or "N/A"),
            ("Most Common IP", data["most_common_ip"] or "N/A"),
            ("First Seen", data["first_seen"] or "N/A"),
            ("Last Seen", data["last_seen"] or "N/A"),
            ("Total Attempts", str(data["total_attempts"])),
            ("Unique IPs", str(data["unique_ips"])),
        ]:
            pdf.cell(60, 8, s(f"{label}:"))
            pdf.cell(0, 8, s(value), ln=True)
        pdf.ln(4)

        if self.country_counts:
            fig = self._build_pie_figure(self.country_counts)
            img_path = path + "_chart_tmp.png"
            fig.savefig(img_path, bbox_inches="tight", dpi=120)
            plt.close(fig)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 10, "Countries", ln=True)
            pdf.image(img_path, w=170)
            import os
            try:
                os.remove(img_path)
            except OSError:
                pass
            pdf.ln(4)
# ------------------------------------------------------------------
#
# ------------------------------------------------------------------
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Ports Observed", ln=True)
        if data["port_range"]:
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, s(f"Port Range: {data['port_range']['lowest']} - {data['port_range']['highest']}"), ln=True)
        pdf.ln(2)

        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Top IPs", ln=True)
        pdf.set_font("Helvetica", "B", 10)
        for w, text in [(45, "IP"), (30, "Attempts"), (55, "Country"), (30, "Risk")]:
            pdf.cell(w, 8, text, border=1)
        pdf.ln()
        pdf.set_font("Helvetica", "", 10)
        for ip in data["top_ips"]:
            pdf.cell(45, 8, s(ip["ip"]), border=1)
            pdf.cell(30, 8, s(ip["attempts"]), border=1, align="C")
            pdf.cell(55, 8, s(ip["country"]), border=1)
            pdf.cell(30, 8, s(ip["risk"]), border=1, align="C")
            pdf.ln()

        try:
            pdf.output(path)
            self.report_status.configure(text=f"PDF report saved to {path}", text_color="#2a2")
        except Exception as e:
            self.report_status.configure(text=f"Failed to save PDF: {e}", text_color="#e33")

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _set_textbox(self, box, text):
        box.configure(state="normal")
        box.delete("0.0", "end")
        box.insert("0.0", text)
        box.configure(state="disabled")


if __name__ == "__main__":
    app = LogAnalyzerApp()
    app.mainloop()