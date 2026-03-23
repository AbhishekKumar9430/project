import time
import queue
import threading
import sys
import io
import signal
from flask import Flask, Response, render_template_string, jsonify
from contextlib import redirect_stdout

# Import your modules
from packet_capture import start_capture
from traffic_analysis import handle_packet
from detection_engine import check_record
from alert_logging import log_alert, generate_report

app = Flask(__name__)
output_queue = queue.Queue()
ids_running = False

class WebIO(io.StringIO):
    def write(self, s):
        sys.__stdout__.write(s)
        sys.__stdout__.flush()
        if s.strip():
            for line in s.splitlines():
                if line.strip():
                    output_queue.put(line.strip())

# --- SIGNAL HANDLER FOR CTRL+C ---
def graceful_exit(sig, frame):
    """Triggered when CTRL+C is pressed in terminal"""
    print("\n" + "!"*50)
    print("🛑 CTRL+C DETECTED - SHUTTING DOWN...")
    try:
        generate_report()
        print("✅ Final Report Saved to ids_logs/")
    except Exception as e:
        print(f"❌ Error during final report: {e}")
    print("!"*50)
    sys.exit(0)

# Register the signal for the terminal
signal.signal(signal.SIGINT, graceful_exit)

def packet_callback(record):
    handle_packet(record)
    alerts = check_record(record)
    for alert in alerts:
        log_alert(alert)

def ids_logic_wrapper():
    try:
        start_capture(packet_callback)
    except Exception:
        pass

def ids_worker():
    global ids_running
    while True:
        if ids_running:
            with redirect_stdout(WebIO()):
                ids_logic_wrapper()
            ids_running = False
        time.sleep(0.5)

threading.Thread(target=ids_worker, daemon=True).start()

# --- ROUTES ---

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>IDS Monitor</title></head>
    <body style="background:#000; color:#0f0; font-family:monospace; padding:20px;">
        <button onclick="fetch('/start')" style="background:#28a745; color:white; padding:10px;">START</button>
        <button onclick="fetch('/stop')" style="background:#dc3545; color:white; padding:10px;">STOP</button>
        <div id="console" style="margin-top:20px; border:1px solid #333; height:400px; overflow-y:scroll; padding:10px; white-space:pre-wrap;"></div>
        <script>
            const consoleBox = document.getElementById('console');
            new EventSource("/stream").onmessage = (e) => {
                consoleBox.innerText += "\\n> " + e.data;
                consoleBox.scrollTop = consoleBox.scrollHeight;
            };
        </script>
    </body>
    </html>
    """)

@app.route('/stream')
def stream():
    def generate():
        while True:
            yield f"data: {output_queue.get()}\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/start')
def start():
    global ids_running
    ids_running = True
    return jsonify(running=True)

@app.route('/stop')
def stop():
    global ids_running
    if ids_running:
        ids_running = False
        with redirect_stdout(WebIO()):
            print("\n🛑 WEB STOP RECEIVED")
            generate_report()
    return jsonify(running=False)

if __name__ == '__main__':
    # Use_reloader=False is critical to allow signal handling
    app.run(threaded=True, debug=False, use_reloader=False)