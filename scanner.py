#!/usr/bin/env python3
# SWILL Security Scanner - GitHub Version
# Работает через GitHub Actions без локального сервера

import os
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
import base64

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.logs = []
        self.html_content = ""
        self.response_headers = {}
        
    def log(self, message, log_type='info'):
        self.logs.append({'message': message, 'type': log_type})
        print(f"[{log_type.upper()}] {message}")
        
    def run_full_scan(self):
        """Запуск полного сканирования"""
        self.log(f"Начинаю сканирование: {self.target_url}", 'success')
        
        # 1. Проверка доступности
        self.log("[1/10] Проверка доступности...", 'info')
        if not self.check_availability():
            return self.generate_report()
            
        # 2. Заголовки
        self.log("[2/10] Анализ заголовков...", 'info')
        self.check_headers()
        
        # 3. SSL
        self.log("[3/10] Проверка SSL...", 'info')
        self.check_ssl()
        
        # 4. Формы
        self.log("[4/10] Поиск форм...", 'info')
        self.find_forms()
        
        # 5. SQL
        self.log("[5/10] SQL Injection...", 'info')
        self.test_sql_injection()
        
        # 6. XSS
        self.log("[6/10] XSS...", 'info')
        self.test_xss()
        
        # 7. Command Injection
        self.log("[7/10] Command Injection...", 'info')
        self.test_command_injection()
        
        # 8. Path Traversal
        self.log("[8/10] Path Traversal...", 'info')
        self.test_path_traversal()
        
        # 9. Directory Listing
        self.log("[9/10] Directory Listing...", 'info')
        self.check_directory_listing()
        
        # 10. Data Security
        self.log("[10/10] Data Security...", 'info')
        self.check_data_security()
        
        self.log("Сканирование завершено", 'success')
        return self.generate_report()
        
    def check_availability(self):
        try:
            req = urllib.request.Request(
                self.target_url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            response = urllib.request.urlopen(req, timeout=15)
            self.log(f"Сайт доступен: {response.status}", 'success')
            self.html_content = response.read().decode('utf-8', errors='ignore')
            self.response_headers = dict(response.headers)
            return True
        except urllib.error.HTTPError as e:
            self.log(f"HTTP ошибка: {e.code}", 'warning')
            try:
                self.html_content = e.read().decode('utf-8', errors='ignore')
                self.response_headers = dict(e.headers)
                return True
            except:
                pass
            return False
        except Exception as e:
            self.log(f"Ошибка: {e}", 'error')
            self.vulnerabilities.append({
                'type': 'Сайт недоступен',
                'severity': 'critical',
                'description': str(e),
                'recommendation': 'Проверьте URL'
            })
            return False
            
    def check_headers(self):
        headers = self.response_headers
        
        if 'X-Frame-Options' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-Frame-Options',
                'severity': 'medium',
                'description': 'Сайт уязвим к clickjacking',
                'recommendation': 'Добавьте X-Frame-Options: DENY'
            })
            
        if 'Content-Security-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует CSP',
                'severity': 'high',
                'description': 'Сайт уязвим к XSS',
                'recommendation': 'Добавьте Content-Security-Policy'
            })
            
        if 'X-XSS-Protection' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-XSS-Protection',
                'severity': 'low',
                'description': 'Заголовок не установлен',
                'recommendation': 'Добавьте X-XSS-Protection: 1; mode=block'
            })
            
        if 'Server' in headers:
            self.vulnerabilities.append({
                'type': 'Раскрытие версии сервера',
                'severity': 'low',
                'description': f'Сервер: {headers["Server"]}',
                'recommendation': 'Скройте версию сервера'
            })
            
    def check_ssl(self):
        if not self.target_url.startswith('https://'):
            self.vulnerabilities.append({
                'type': 'Отсутствует SSL/TLS',
                'severity': 'critical',
                'description': 'Данные передаются без шифрования',
                'recommendation': 'Используйте HTTPS'
            })
            
    def find_forms(self):
        if not self.html_content:
            return
            
        forms = re.findall(r'<form(.*?)</form>', self.html_content, re.DOTALL)
        self.log(f"Найдено форм: {len(forms)}", 'info')
        
    def test_sql_injection(self):
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "' UNION SELECT NULL--"
        ]
        
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'mysqli_fetch', 'PostgreSQL',
            'ORA-', 'SQLite', 'SQLSTATE', 'syntax error'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                for error in sql_errors:
                    if error.lower() in content.lower():
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'critical',
                            'description': f'SQL-инъекция: {payload}',
                            'recommendation': 'Используйте prepared statements',
                            'payload': payload
                        })
                        self.log(f"SQL Injection: {payload}", 'critical')
                        return
            except:
                continue
                
    def test_xss(self):
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if payload in content:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'severity': 'high',
                        'description': f'XSS: {payload}',
                        'recommendation': 'Экранируйте ввод',
                        'payload': payload
                    })
                    self.log(f"XSS: {payload}", 'critical')
                    return
            except:
                continue
                
    def test_command_injection(self):
        payloads = ['; ls -la', '; pwd', '&& whoami', '| ls']
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?cmd={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root' in content or 'bin' in content:
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'critical',
                        'description': f'Инъекция команд: {payload}',
                        'recommendation': 'Не передавайте ввод в команды',
                        'payload': payload
                    })
                    self.log(f"Command Injection: {payload}", 'critical')
                    return
            except:
                continue
                
    def test_path_traversal(self):
        payloads = ['../../../etc/passwd', '../../etc/passwd']
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}/{payload}"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root:' in content:
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'high',
                        'description': f'Path Traversal: {payload}',
                        'recommendation': 'Проверяйте пути',
                        'payload': payload
                    })
                    self.log(f"Path Traversal: {payload}", 'critical')
                    return
            except:
                continue
                
    def check_directory_listing(self):
        paths = ['/admin/', '/backup/', '/config/']
        
        for path in paths:
            try:
                test_url = self.target_url.rstrip('/') + path
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'Index of' in content:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'medium',
                        'description': f'Открытый листинг: {test_url}',
                        'recommendation': 'Отключите directory listing'
                    })
                    self.log(f"Directory Listing: {test_url}", 'warning')
            except:
                continue
                
    def check_data_security(self):
        if self.target_url.startswith('http://'):
            self.vulnerabilities.append({
                'type': 'Данные без шифрования',
                'severity': 'critical',
                'description': 'HTTP без шифрования',
                'recommendation': 'Используйте HTTPS'
            })
            
    def generate_report(self):
        critical = len([v for v in self.vulnerabilities if v['severity'] == 'critical'])
        high = len([v for v in self.vulnerabilities if v['severity'] == 'high'])
        medium = len([v for v in self.vulnerabilities if v['severity'] == 'medium'])
        low = len([v for v in self.vulnerabilities if v['severity'] == 'low'])
        
        score = 100
        score -= critical * 20
        score -= high * 10
        score -= medium * 5
        score -= low * 2
        score = max(0, min(100, score))
        
        report = {
            'target': self.target_url,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'score': score,
            'criticalCount': critical,
            'highCount': high,
            'mediumCount': medium,
            'lowCount': low,
            'totalVulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'logs': self.logs
        }
        
        return report


def generate_text_report(report):
    """Генерация текстового отчета"""
    text = '=' * 60 + '\n'
    text += 'SWILL SECURITY SCAN REPORT\n'
    text += '=' * 60 + '\n\n'
    text += f"Дата: {report['date']}\n"
    text += f"Цель: {report['target']}\n"
    text += f"Оценка: {report['score']}/100\n\n"
    text += '-' * 60 + '\n'
    text += 'СТАТИСТИКА\n'
    text += '-' * 60 + '\n\n'
    text += f"Критических: {report['criticalCount']}\n"
    text += f"Высоких: {report['highCount']}\n"
    text += f"Средних: {report['mediumCount']}\n"
    text += f"Низких: {report['lowCount']}\n"
    text += f"Всего: {report['totalVulnerabilities']}\n\n"
    
    if report['vulnerabilities']:
        text += '-' * 60 + '\n'
        text += 'УЯЗВИМОСТИ\n'
        text += '-' * 60 + '\n\n'
        
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            text += f"{i}. {vuln['type']}\n"
            text += f"   Severity: {vuln['severity'].upper()}\n"
            text += f"   Description: {vuln['description']}\n"
            text += f"   Recommendation: {vuln['recommendation']}\n"
            if vuln.get('payload'):
                text += f"   Payload: {vuln['payload']}\n"
            text += '\n'
    else:
        text += 'Уязвимостей не обнаружено.\n'
        
    text += '=' * 60 + '\n'
    text += 'Generated by SWILL Security Scanner\n'
    text += 'TG: t.me/Swill_Way\n'
    text += '=' * 60 + '\n'
    
    return text


def main():
    """Главная функция"""
    print("""
    ╔══════════════════════════════════════════╗
    ║     SWILL Security Scanner              ║
    ║     GitHub Actions Version              ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Получение URL из аргументов или переменной окружения
    target = None
    
    if len(os.sys.argv) > 1:
        target = os.sys.argv[1]
    elif 'TARGET_URL' in os.environ:
        target = os.environ['TARGET_URL']
    else:
        target = input("Введите URL для сканирования: ")
        
    if not target:
        print("URL не указан")
        return
        
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target
        
    # Запуск сканирования
    scanner = SecurityScanner(target)
    report = scanner.run_full_scan()
    
    # Генерация текстового отчета
    text_report = generate_text_report(report)
    
    # Сохранение отчета
    report_file = 'security_report.txt'
    with open(report_file, 'w') as f:
        f.write(text_report)
        
    # Сохранение JSON
    json_file = 'security_report.json'
    with open(json_file, 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"\nОтчет сохранен: {report_file}")
    print(f"JSON сохранен: {json_file}")
    print(f"\nОценка безопасности: {report['score']}/100")
    
    # Вывод отчета
    print("\n" + text_report)
    
    # Для GitHub Actions - установка output
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"score={report['score']}\n")
            f.write(f"critical={report['criticalCount']}\n")
            f.write(f"high={report['highCount']}\n")
            f.write(f"total={report['totalVulnerabilities']}\n")


if __name__ == '__main__':
    main()
