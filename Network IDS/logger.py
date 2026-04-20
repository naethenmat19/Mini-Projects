import datetime
from config import LOG_FILE

# GUI logger callback
gui_logger = None

def set_gui_logger(func):
    global gui_logger
    gui_logger = func


def get_separator(message):
    # Dynamic separator based on message type
    if "[ALERT]" in message:
        return "-" * 100
    elif "[WARNING]" in message:
        return "-" * 100
    elif "[INFO]" in message:
        return "-" * 100
    else:
        return "-" * 100


def log_alert(message):
    timestamp = datetime.datetime.now()
    log_message = f"[{timestamp}] {message}"

    separator = get_separator(message)

    # ===== CONSOLE OUTPUT =====
    print("\n" + separator)
    print(log_message)
    print(separator + "\n")

    # ===== GUI OUTPUT =====
    if gui_logger:
        gui_logger(separator)
        gui_logger(log_message)
        gui_logger(separator)

    # ===== FILE LOGGING =====
    with open(LOG_FILE, "a") as f:
        f.write(separator + "\n")
        f.write(log_message + "\n")
        f.write(separator + "\n")
