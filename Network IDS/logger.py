# -*- coding: utf-8 -*-
"""
logger.py - Alert logging for Network IDS
==========================================
Writes alerts to the console, an optional GUI callback, and the log file.
"""

import datetime
from config import LOG_FILE

# Optional GUI logger callback (set by gui.py via set_gui_logger)
_gui_logger = None


def set_gui_logger(func):
    """Register a callable that will receive each log message string."""
    global _gui_logger
    _gui_logger = func


def log_alert(message: str) -> None:
    """
    Log a timestamped alert message to:
      - stdout (console)
      - the registered GUI callback (if any)
      - the log file defined in config.LOG_FILE
    """
    timestamp   = datetime.datetime.now()
    log_message = f"[{timestamp}] {message}"
    separator   = "-" * 100

    # Console
    print(f"\n{separator}")
    print(log_message)
    print(f"{separator}\n")

    # GUI (thread-safe: gui.py enqueues via queue.Queue)
    if _gui_logger:
        _gui_logger(separator)
        _gui_logger(log_message)
        _gui_logger(separator)

    # File
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{separator}\n{log_message}\n{separator}\n")