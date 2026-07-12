"""
Vivid Casino Engine — Content Delivery Server

Hosts game modules and assets for dynamic loading.
Serves DLLs, scripts, and configuration files to player clients.
"""

import http.server
import socketserver
import os

CONTENT_PORT = 8080
CONTENT_DIR = "modules"

class ContentHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=CONTENT_DIR, **kwargs)
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        super().do_GET()
    
    def log_message(self, format, *args):
        pass  # Suppress request logging

def start_server():
    os.makedirs(CONTENT_DIR, exist_ok=True)
    with socketserver.TCPServer(("0.0.0.0", CONTENT_PORT), ContentHandler) as httpd:
        print(f"[*] Content server on port {CONTENT_PORT}")
        httpd.serve_forever()

if __name__ == '__main__':
    start_server()
