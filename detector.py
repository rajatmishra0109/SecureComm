import time
import threading

_detection_active = False
_detection_thread = None

def _detection_loop(st):
    global _detection_active
    _detection_active = True
    log_path = "logs/detection_log.txt"
    while _detection_active:
        # Simulate detection log writing
        with open(log_path, "a") as f:
            f.write(f"Detection running at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        time.sleep(2)  # Simulate detection interval

def start_detection(st):
    global _detection_thread, _detection_active
    if not _detection_active:
        _detection_thread = threading.Thread(target=_detection_loop, args=(st,), daemon=True)
        _detection_thread.start()
        st.info("Detection started.")
    else:
        st.warning("Detection is already running.")

def stop_detection():
    global _detection_active
    _detection_active = False