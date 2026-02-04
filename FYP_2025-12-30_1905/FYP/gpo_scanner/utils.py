# utils.py
import subprocess
import json
import shutil
import ctypes

def run_powershell(cmd, timeout=60):
    """
    執行 PowerShell 指令字串，回傳 (ok: bool, result: dict|list|str)
    - 若 PowerShell 回傳 JSON，解析為 dict/list
    - 若回傳空字串，回傳 ""
    - 若 PowerShell 回傳錯誤或非 JSON，回傳原始 stdout/stderr 字串
    """
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
    except Exception as e:
        return False, f"Exception: {e}"

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    if completed.returncode != 0:
        # 優先回傳 stderr（若有），否則回傳 stdout
        return False, stderr or stdout or f"Return code {completed.returncode}"

    if not stdout:
        return True, ""

    # 嘗試解析 JSON，失敗就回傳原始字串
    try:
        parsed = json.loads(stdout)
        return True, parsed
    except Exception:
        return True, stdout

def is_admin():
    """
    回傳 True 若目前進程以系統管理員權限執行（Windows）
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def cmd_exists(cmd_name):
    """
    檢查系統是否能找到指定的可執行檔或命令（簡單檢查）
    """
    return shutil.which(cmd_name) is not None
