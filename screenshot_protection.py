# screenshot_protection.py

import sys
import threading
import ctypes
from ctypes import wintypes

# Optional: block Print Screen with the 'keyboard' library
try:
    import keyboard
    _HAS_KEYBOARD = True
except ImportError:
    _HAS_KEYBOARD = False

# Windows constants and APIs
if sys.platform == "win32":
    user32 = ctypes.windll.user32
    SetWindowDisplayAffinity = user32.SetWindowDisplayAffinity
    GetForegroundWindow       = user32.GetForegroundWindow

    SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    SetWindowDisplayAffinity.restype  = wintypes.BOOL

    # Restrict capture of this window to the monitor only
    WDA_NONE    = 0x0
    WDA_MONITOR = 0x1

    def protect_foreground_window(interval: float = 0.5):
        """
        Every `interval` seconds, re-apply the display affinity
        to whatever window is in the foreground.
        """
        while True:
            hwnd = GetForegroundWindow()
            if hwnd:
                SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
            ctypes.windll.kernel32.Sleep(int(interval * 1000))

    def start_protection(interval: float = 0.5):
        """
        Spawn a daemon thread that continuously protects the foreground window.
        """
        t = threading.Thread(
            target=protect_foreground_window,
            args=(interval,),
            daemon=True
        )
        t.start()

else:
    def start_protection(interval: float = 0.5):
        raise NotImplementedError("Screenshot protection only implemented on Windows")


def block_prtsc():
    """
    If `keyboard` is installed and running as admin,
    block the PrintScreen and Alt+PrintScreen keys.
    """
    if not _HAS_KEYBOARD:
        return

    # Blocks common screenshot hotkeys
    for combo in ['print_screen', 'alt+print_screen']:
        try:
            keyboard.block_key(combo)
        except Exception:
            pass


def initialize_screenshot_protection(interval: float = 0.5):
    """
    Call this at app startup to:
      1) Block PrintScreen keys
      2) Start the window-affinity protection loop
    """
    if sys.platform == "win32":
        block_prtsc()
        start_protection(interval)
    else:
        print("Screenshot protection unavailable on this OS")
