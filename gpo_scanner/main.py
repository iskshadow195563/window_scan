import tkinter as tk
from tkinter import messagebox
import subprocess
import sys

# 需要的 pip 套件清單
REQUIRED_PACKAGES = [
    "tkinter",      # GUI
    "reportlab",    # PDF 輸出
    "chartjs",      # 報表用 Chart.js (通常用 CDN，不需 pip)
    "psutil",       # 系統資訊
    # 其他你程式用到的套件...
]

def install_packages(packages):
    for pkg in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        except subprocess.CalledProcessError:
            print(f"安裝 {pkg} 失敗")

def confirm_and_install():
    root = tk.Tk()
    root.withdraw()  # 隱藏主視窗
    answer = messagebox.askyesno("安裝套件", "是否要安裝此程式所需的 pip 套件？")
    if answer:
        install_packages(REQUIRED_PACKAGES)
    root.destroy()

confirm_and_install()


from gui import run_app
run_app()
