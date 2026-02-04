# gui.py
# 完整 GUI 主程式（調整右側比例與分數顯示為水平條，改善版面比例）
# 依賴檔案：checks.py, utils.py, report.py, report_html.py
# 使用：在專案資料夾中以管理員權限執行 `python main.py`

import os
import datetime
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

from checks import CHECKS
from utils import run_powershell, is_admin
import report
import report_html

def compute_weighted_score(results):
    total_weight = 0
    score_sum = 0
    for category, items in results.items():
        for name, res, weight in items:
            total_weight += weight
            if res == "PASS":
                score_sum += weight
    if total_weight == 0:
        return 0.0
    return (score_sum / total_weight) * 100.0

class GPOScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Windows Server GPO 安全掃描工具")
        master.geometry("1000x700")
        master.minsize(900,600)
        master.resizable(True, True)

        # Top controls
        top_frame = tk.Frame(master)
        top_frame.pack(fill=tk.X, padx=8, pady=6)

        tk.Label(top_frame, text="輸出格式：", font=("Arial", 10)).pack(side=tk.LEFT)
        self.format_var = tk.StringVar(value="TXT")
        ttk.Combobox(top_frame, textvariable=self.format_var, values=["TXT", "HTML", "PDF"], width=8, state="readonly").pack(side=tk.LEFT, padx=6)

        tk.Button(top_frame, text="列出所有 GPO", command=self.list_all_gpos).pack(side=tk.LEFT, padx=6)
        tk.Button(top_frame, text="全選", command=self.select_all).pack(side=tk.LEFT, padx=6)
        tk.Button(top_frame, text="全不選", command=self.deselect_all).pack(side=tk.LEFT, padx=6)
        tk.Button(top_frame, text="開始掃描", bg="#4CAF50", fg="white", command=self.start_scan).pack(side=tk.RIGHT, padx=6)

        # Output folder selection
        folder_frame = tk.Frame(master)
        folder_frame.pack(fill=tk.X, padx=8, pady=(0,6))
        tk.Label(folder_frame, text="輸出資料夾：", font=("Arial", 10)).pack(side=tk.LEFT)
        default_folder = os.path.join(os.getcwd(), "reports", datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.output_folder_var = tk.StringVar(value=default_folder)
        self.folder_entry = tk.Entry(folder_frame, textvariable=self.output_folder_var, width=60)
        self.folder_entry.pack(side=tk.LEFT, padx=6)
        tk.Button(folder_frame, text="選擇資料夾", command=self.choose_folder).pack(side=tk.LEFT, padx=6)
        tk.Button(folder_frame, text="開啟資料夾", command=self.open_folder).pack(side=tk.LEFT, padx=6)
        tk.Button(folder_frame, text="開啟網頁檢視器", command=self.open_report_viewer).pack(side=tk.LEFT, padx=6)
        tk.Button(folder_frame, text="環境檢查", command=self.run_env_check).pack(side=tk.LEFT, padx=6)

        # Middle: scrollable checks list
        mid_frame = tk.Frame(master)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        canvas = tk.Canvas(mid_frame)
        scrollbar = ttk.Scrollbar(mid_frame, orient="vertical", command=canvas.yview)
        self.check_frame = tk.Frame(canvas)
        self.check_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.check_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Build checkboxes from CHECKS
        self.vars = {}  # name -> (tk.BooleanVar, func, weight, category)
        for category, items in CHECKS.items():
            lbl = tk.Label(self.check_frame, text=category, font=("Arial", 11, "bold"))
            lbl.pack(anchor="w", pady=(8,0))
            for name, func, weight in items:
                var = tk.BooleanVar(value=True)
                chk = tk.Checkbutton(self.check_frame, text=f"{name} (權重 {weight})", variable=var, anchor="w", justify="left", wraplength=520)
                chk.pack(anchor="w", padx=12)
                self.vars[name] = (var, func, weight, category)

        # ---------- Bottom: adjusted two-column output area ----------
        bottom_frame = tk.Frame(master)
        bottom_frame.pack(fill=tk.BOTH, padx=8, pady=6, expand=True)

        # Left: main scan output (占更大比例)
        left = tk.Frame(bottom_frame)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left, text="掃描輸出 / 即時訊息").pack(anchor="w")
        self.output = scrolledtext.ScrolledText(left, height=14, font=("Consolas", 10))
        self.output.pack(fill=tk.BOTH, expand=True)

        # Right container: narrower, score uses horizontal bar for compactness
        right_container = tk.Frame(bottom_frame, width=300)
        right_container.pack(side=tk.RIGHT, fill=tk.Y)
        right_container.pack_propagate(False)

        # Top row: env title and compact score aligned horizontally
        right_top = tk.Frame(right_container)
        right_top.pack(fill=tk.X, pady=(0,6), padx=4)

        # Environment title (left)
        env_title_frame = tk.Frame(right_top)
        env_title_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(env_title_frame, text="環境檢查", font=("Arial", 10, "bold")).pack(anchor="w")

        # Compact score (right) - horizontal progressbar and small label
        score_frame = tk.Frame(right_top, width=140)
        score_frame.pack(side=tk.RIGHT, fill=tk.Y)
        tk.Label(score_frame, text="系統安全分數", font=("Arial", 10, "bold")).pack(anchor="e")
        self.score_var = tk.DoubleVar(value=0.0)
        # horizontal progressbar for better proportion
        self.progress = ttk.Progressbar(score_frame, orient="horizontal", length=120, mode="determinate", maximum=100, variable=self.score_var)
        self.progress.pack(anchor="e", pady=4)
        self.score_label = tk.Label(score_frame, textvariable=self.score_var, font=("Arial", 12))
        self.score_label.pack(anchor="e")

        # Right bottom: environment check output (獨立且高度適中)
        tk.Label(right_container, text="環境檢查輸出", font=("Arial", 10)).pack(anchor="w", padx=6)
        self.env_output = scrolledtext.ScrolledText(right_container, width=40, height=12, font=("Consolas", 10))
        self.env_output.pack(fill=tk.BOTH, expand=True, padx=6, pady=(4,0))

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(master, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor="w")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # track last html report path
        self.last_html_report = None

    # ---------- folder helpers ----------
    def choose_folder(self):
        chosen = filedialog.askdirectory(initialdir=os.path.dirname(self.output_folder_var.get()) or os.getcwd())
        if chosen:
            self.output_folder_var.set(chosen)

    def open_folder(self):
        folder = self.output_folder_var.get()
        if not folder:
            messagebox.showwarning("警告", "尚未設定輸出資料夾")
            return
        if not os.path.exists(folder):
            messagebox.showwarning("警告", "資料夾不存在")
            return
        try:
            os.startfile(folder)
        except Exception as e:
            messagebox.showerror("錯誤", f"無法開啟資料夾: {e}")

    def open_report_viewer(self):
        if not self.last_html_report:
            messagebox.showwarning("尚未產生報告", "請先執行掃描以產生 HTML 報告")
            return
        if not os.path.exists(self.last_html_report):
            messagebox.showerror("檔案不存在", f"找不到報告檔案：{self.last_html_report}")
            return
        try:
            os.startfile(self.last_html_report)
        except Exception as e:
            messagebox.showerror("錯誤", f"無法開啟報告檔案: {e}")

    # ---------- selection helpers ----------
    def select_all(self):
        for name, (var, *_ ) in self.vars.items():
            var.set(True)

    def deselect_all(self):
        for name, (var, *_ ) in self.vars.items():
            var.set(False)

    # ---------- list GPO ----------
    def list_all_gpos(self):
        self.output.insert(tk.END, f"[{datetime.datetime.now()}] 列出所有 GPO...\n")
        self.status_var.set("列出 GPO 中...")
        ok, res = run_powershell("Get-GPO -All | Select-Object DisplayName,Id | ConvertTo-Json -Compress")
        if not ok:
            self.output.insert(tk.END, f"列出 GPO 失敗: {res}\n\n")
            self.status_var.set("Ready")
            return
        try:
            gpos = res if isinstance(res, list) else [res]
            for g in gpos:
                name = g.get("DisplayName","<no name>") if isinstance(g, dict) else str(g)
                gid = g.get("Id","") if isinstance(g, dict) else ""
                self.output.insert(tk.END, f"GPO: {name} | ID: {gid}\n")
            self.output.insert(tk.END, "\n")
            self.status_var.set("列出 GPO 完成")
        except Exception as e:
            self.output.insert(tk.END, f"解析 GPO 失敗: {e}\n")
            self.status_var.set("Ready")

    # ---------- environment check (writes to env_output) ----------
    def run_env_check(self):
        """
        檢查必要環境：是否以 admin 執行、常用 cmdlet 是否存在（BitLocker、LocalGroupMember、AuditPol、Smb、Firewall）
        輸出寫入 self.env_output（獨立輸出框）
        """
        def _check():
            # 清除舊內容以避免堆疊
            try:
                self.env_output.delete("1.0", tk.END)
            except:
                pass
            self.env_output.insert(tk.END, f"[{datetime.datetime.now()}] 執行環境檢查...\n")
            self.env_output.see(tk.END)
            self.status_var.set("環境檢查中...")
            missing = []
            # 1) admin
            if not is_admin():
                self.env_output.insert(tk.END, "警告: 建議以系統管理員權限執行掃描以取得完整結果\n")
            else:
                self.env_output.insert(tk.END, "已偵測到系統管理員權限\n")
            # 2) 常用 cmdlet 檢查
            cmdlets = [
                ("Get-BitLockerVolume", "BitLocker 管理模組"),
                ("Get-LocalGroupMember", "本機群組管理"),
                ("AuditPol", "稽核策略工具"),
                ("Get-SmbServerConfiguration", "SMB 設定"),
                ("Get-NetFirewallRule", "防火牆規則"),
                ("Get-GPO", "GroupPolicy 模組 (需 RSAT/AD 模組)"),
            ]
            for cmd, desc in cmdlets:
                ok, res = run_powershell(f"Get-Command {cmd} -ErrorAction SilentlyContinue | Select-Object -Property Name | ConvertTo-Json -Compress")
                if not ok or (isinstance(res, str) and res.strip() == ""):
                    missing.append((cmd, desc))
                    self.env_output.insert(tk.END, f"缺少: {desc} ({cmd})\n")
                else:
                    self.env_output.insert(tk.END, f"可用: {desc} ({cmd})\n")
            if missing:
                self.env_output.insert(tk.END, "\n建議：安裝或啟用缺少的模組/功能，或在支援該功能的主機上執行掃描。\n")
            else:
                self.env_output.insert(tk.END, "\n環境檢查通過，常用 cmdlet 均可用。\n")
            self.env_output.see(tk.END)
            self.status_var.set("Ready")

        t = threading.Thread(target=_check)
        t.daemon = True
        t.start()

    # ---------- scan control ----------
    def start_scan(self):
        t = threading.Thread(target=self.run_scan)
        t.daemon = True
        t.start()

    def run_scan(self):
        """
        執行掃描主流程（在背景執行緒中）
        """
        # 收集選取項目
        selected = []
        for name, (var, func, weight, category) in self.vars.items():
            if var.get():
                selected.append((name, func, weight, category))
        if not selected:
            messagebox.showerror("錯誤", "請至少選擇一個檢查項目")
            return

        # 準備輸出資料夾
        folder = self.output_folder_var.get().strip()
        if not folder:
            folder = os.path.join(os.getcwd(), "reports", datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
            self.output_folder_var.set(folder)
        try:
            os.makedirs(folder, exist_ok=True)
        except Exception as e:
            messagebox.showerror("錯誤", f"無法建立資料夾: {e}")
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        basepath = os.path.join(folder, f"scan_results_{timestamp}")
        txt_path = basepath + ".txt"
        html_path = basepath + ".html"
        pdf_path = basepath + ".pdf"

        # 開始逐項掃描
        self.output.insert(tk.END, f"[{datetime.datetime.now()}] 開始掃描 {len(selected)} 項...\n")
        self.output.see(tk.END)
        self.status_var.set("掃描中...")
        results_by_category = {}

        for idx, (name, func, weight, category) in enumerate(selected, start=1):
            self.output.insert(tk.END, f"[{idx}/{len(selected)}] 執行: {name}\n")
            self.output.see(tk.END)
            try:
                res = func()
            except Exception as e:
                res = f"ERROR: {e}"
            # 收集
            if category not in results_by_category:
                results_by_category[category] = []
            results_by_category[category].append((name, res, weight))
            # 顯示
            self.output.insert(tk.END, f"結果: {res}\n\n")
            self.output.see(tk.END)
            if res == "FAIL" or (isinstance(res, str) and res.startswith("ERROR")):
                self.output.insert(tk.END, f"警告: 檢查失敗 -> {name}\n\n")
                self.output.see(tk.END)

        # 計算分數
        try:
            score = compute_weighted_score(results_by_category)
        except Exception:
            score = 0.0
        self.score_var.set(round(score, 2))
        self.output.insert(tk.END, f"[完成] 掃描完成。系統安全評分: {score:.2f}%\n")
        self.output.see(tk.END)
        self.status_var.set("掃描完成")

        # 產生報告
        try:
            # TXT
            report.generate_txt(txt_path, results_by_category, score)
            self.output.insert(tk.END, f"TXT 報告已輸出: {os.path.abspath(txt_path)}\n")
            # HTML（獨立模組）
            try:
                report_html.generate_html(html_path, results_by_category, score)
                self.last_html_report = os.path.abspath(html_path)
                self.output.insert(tk.END, f"HTML 報告已輸出: {self.last_html_report}\n")
            except Exception as e_html:
                self.output.insert(tk.END, f"HTML 產生失敗: {e_html}\n")
            # PDF（若選擇）
            if self.format_var.get() == "PDF":
                try:
                    report.generate_pdf(pdf_path, results_by_category, score)
                    self.output.insert(tk.END, f"PDF 報告已輸出: {os.path.abspath(pdf_path)}\n")
                except Exception as e_pdf:
                    self.output.insert(tk.END, f"PDF 產生失敗（可能缺少 reportlab）: {e_pdf}\n")
            self.output.insert(tk.END, f"所有報告已儲存在資料夾: {os.path.abspath(folder)}\n")
            self.output.see(tk.END)
            messagebox.showinfo("完成", f"掃描完成，報告已輸出到:\n{os.path.abspath(folder)}")
        except Exception as e:
            self.output.insert(tk.END, f"報告產生失敗: {e}\n")
            self.output.see(tk.END)
            messagebox.showerror("錯誤", f"報告產生失敗: {e}")

        self.status_var.set("Ready")

def run_app():
    root = tk.Tk()
    app = GPOScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_app()
