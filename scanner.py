#!/usr/bin/env python3
# SWILL Security Scanner - GitHub Actions Version
# Репозиторий: kektola70-sketch/.-exe-for-hacks

import os
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
import base64
import sys

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
        self.log("=" * 50, 'info')
        
        # 1. Проверка доступности
        self.log("[1/10] Проверка доступности...", 'info')
        if not self.check_availability():
            return self.generate_report()
            
        # 2. Заголовки
        self.log("[2/10] Анализ HTTP заголовков...", 'info')
        self.check_headers()
        
        # 3. SSL
        self.log("[3/10] Проверка SSL/TLS...", 'info')
        self.check_ssl()
        
        # 4. Формы
        self.log("[4/10] Поиск форм...", 'info')
        self.find_forms()
        
        # 5. SQL Injection
        self.log("[5/10] Тестирование SQL-инъекций...", 'info')
        self.test_sql_injection()
        
        # 6. XSS
        self.log("[6/10] Тестирование XSS...", 'info')
        self.test_xss()
        
        # 7. Command Injection
        self.log("[7/10] Тестирование инъекций команд...", 'info')
        self.test_command_injection()
        
        # 8. Path Traversal
        self.log("[8/10] Тестирование Path Traversal...", 'info')
        self.test_path_traversal()
        
        # 9. Directory Listing
        self.log("[9/10] Проверка Directory Listing...", 'info')
        self.check_directory_listing()
        
        # 10. Data Security
        self.log("[10/10] Анализ безопасности данных...", 'info')
        self.check_data_security()
        
        self.log("Сканирование завершено", 'success')
        return self.generate_report()
        
    def check_availability(self):
        try:
            req = urllib.request.Request(
                self.target_url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response = urllib.request.urlopen(req, timeout=15)
            self.log(f"Сайт доступен. Статус: {response.status}", 'success')
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
                
            self.vulnerabilities.append({
                'type': f'HTTP ошибка {e.code}',
                'severity': 'medium',
                'description': f'Сервер вернул код {e.code}',
                'recommendation': 'Проверьте доступность ресурса'
            })
            return False
            
        except urllib.error.URLError as e:
            self.log(f"Ошибка подключения: {e.reason}", 'error')
            self.vulnerabilities.append({
                'type': 'Сайт недоступен',
                'severity': 'critical',
                'description': f'Не удалось подключиться: {e.reason}',
                'recommendation': 'Проверьте правильность URL'
            })
            return False
            
        except Exception as e:
            self.log(f"Ошибка: {e}", 'error')
            self.vulnerabilities.append({
                'type': 'Ошибка сканирования',
                'severity': 'critical',
                'description': str(e),
                'recommendation': 'Проверьте настройки'
            })
            return False
            
    def check_headers(self):
        headers = self.response_headers
        
        # X-Frame-Options
        if 'X-Frame-Options' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-Frame-Options',
                'severity': 'medium',
                'description': 'Сайт уязвим к clickjacking атакам',
                'recommendation': 'Добавьте заголовок X-Frame-Options: DENY'
            })
            self.log("X-Frame-Options отсутствует", 'warning')
        else:
            self.log(f"X-Frame-Options: {headers['X-Frame-Options']}", 'success')
            
        # Content-Security-Policy
        if 'Content-Security-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует Content-Security-Policy',
                'severity': 'high',
                'description': 'Сайт уязвим к XSS атакам',
                'recommendation': 'Добавьте заголовок Content-Security-Policy'
            })
            self.log("CSP отсутствует", 'warning')
        else:
            self.log("CSP установлен", 'success')
            
        # X-XSS-Protection
        if 'X-XSS-Protection' not in headers:
            self.vulnerabilities.append({
                'type': 'Отсутствует X-XSS-Protection',
                'severity': 'low',
                'description': 'Заголовок X-XSS-Protection не установлен',
                'recommendation': 'Добавьте X-XSS-Protection: 1; mode=block'
            })
            
        # Server
        if 'Server' in headers:
            self.vulnerabilities.append({
                'type': 'Раскрытие версии сервера',
                'severity': 'low',
                'description': f'Сервер: {headers["Server"]}',
                'recommendation': 'Скройте версию сервера'
            })
            self.log(f"Сервер: {headers['Server']}", 'warning')
            
        # X-Powered-By
        if 'X-Powered-By' in headers:
            self.vulnerabilities.append({
                'type': 'Раскрытие технологии',
                'severity': 'low',
                'description': f'Технология: {headers["X-Powered-By"]}',
                'recommendation': 'Уберите заголовок X-Powered-By'
            })
            
    def check_ssl(self):
        if not self.target_url.startswith('https://'):
            self.vulnerabilities.append({
                'type': 'Отсутствует SSL/TLS',
                'severity': 'critical',
                'description': 'Данные передаются без шифрования',
                'recommendation': 'Установите SSL-сертификат и используйте HTTPS'
            })
            self.log("HTTPS не используется", 'critical')
        else:
            self.log("HTTPS используется", 'success')
            
    def find_forms(self):
        if not self.html_content:
            return
            
        forms = re.findall(r'<form(.*?)</form>', self.html_content, re.DOTALL)
        self.log(f"Найдено форм: {len(forms)}", 'info')
        
        for form in forms:
            # Поиск полей ввода
            inputs = re.findall(r'<input[^>]*type=["\']([^"\']*)["\'][^>]*>', form)
            if 'password' in inputs:
                self.log("Обнаружена форма входа", 'info')
                
    def test_sql_injection(self):
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "' UNION SELECT NULL--",
            "1 OR 1=1 --"
        ]
        
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'mysqli_fetch', 'PostgreSQL',
            'ORA-', 'SQLite', 'SQLSTATE', 'syntax error',
            'unclosed quotation', 'SQL command not properly ended',
            'Warning: mysql', 'You have an error in your SQL syntax'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
                req = urllib.request.Request(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                for error in sql_errors:
                    if error.lower() in content.lower():
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'critical',
                            'description': f'Обнаружена SQL-инъекция с payload: {payload}',
                            'recommendation': 'Используйте параметризованные запросы (prepared statements)',
                            'payload': payload
                        })
                        self.log(f"SQL Injection найден: {payload}", 'critical')
                        return
                        
            except:
                continue
                
        self.log("SQL-инъекций не обнаружено", 'success')
        
    def test_xss(self):
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
                req = urllib.request.Request(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if payload in content:
                    self.vulnerabilities.append({
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'high',
                        'description': f'Обнаружена XSS с payload: {payload}',
                        'recommendation': 'Экранируйте пользовательский ввод',
                        'payload': payload
                    })
                    self.log(f"XSS найден: {payload}", 'critical')
                    return
                    
            except:
                continue
                
        self.log("XSS не обнаружен", 'success')
        
    def test_command_injection(self):
        payloads = [
            '; ls -la',
            '; pwd',
            '; whoami',
            '&& whoami',
            '| ls -la'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?cmd={urllib.parse.quote(payload)}"
                req = urllib.request.Request(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root' in content or 'bin' in content or 'vulnerable' in content:
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'critical',
                        'description': f'Обнаружена инъекция команд: {payload}',
                        'recommendation': 'Не передавайте пользовательский ввод в системные команды',
                        'payload': payload
                    })
                    self.log(f"Command Injection: {payload}", 'critical')
                    return
                    
            except:
                continue
                
        self.log("Инъекций команд не обнаружено", 'success')
        
    def test_path_traversal(self):
        payloads = [
            '../../../etc/passwd',
            '../../etc/passwd',
            '....//....//etc/passwd'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}/{payload}"
                req = urllib.request.Request(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root:' in content or 'admin:' in content:
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'high',
                        'description': f'Обнаружен Path Traversal: {payload}',
                        'recommendation': 'Проверяйте и экранируйте пути к файлам',
                        'payload': payload
                    })
                    self.log(f"Path Traversal: {payload}", 'critical')
                    return
                    
            except:
                continue
                
        self.log("Path Traversal не обнаружен", 'success')
        
    def check_directory_listing(self):
        paths = ['/admin/', '/backup/', '/config/', '/uploads/']
        
        for path in paths:
            try:
                test_url = self.target_url.rstrip('/') + path
                req = urllib.request.Request(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                response = urllib.request.urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'Index of' in content or 'Directory listing' in content:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'medium',
                        'description': f'Открытый листинг директории: {test_url}',
                        'recommendation': 'Отключите directory listing на сервере'
                    })
                    self.log(f"Directory Listing: {test_url}", 'warning')
                    
            except:
                continue
                
        self.log("Проверка Directory Listing завершена", 'success')
        
    def check_data_security(self):
        if self.target_url.startswith('http://'):
            self.vulnerabilities.append({
                'type': 'Передача данных без шифрования',
                'severity': 'critical',
                'description': 'Данные передаются по незащищенному HTTP',
                'recommendation': 'Используйте HTTPS'
            })
            
        if self.html_content:
            sensitive_patterns = ['password', 'api_key', 'secret', 'token', 'private_key']
            for pattern in sensitive_patterns:
                if pattern in self.html_content.lower():
                    self.vulnerabilities.append({
                        'type': 'Раскрытие конфиденциальной информации',
                        'severity': 'high',
                        'description': f'Обнаружено "{pattern}" в HTML',
                        'recommendation': 'Уберите конфиденциальные данные из HTML'
                    })
                    break
                    
        self.log("Анализ данных завершен", 'success')
        
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
    text += 'СТАТИСТИКА УЯЗВИМОСТЕЙ\n'
    text += '-' * 60 + '\n\n'
    text += f"Критических: {report['criticalCount']}\n"
    text += f"Высоких: {report['highCount']}\n"
    text += f"Средних: {report['mediumCount']}\n"
    text += f"Низких: {report['lowCount']}\n"
    text += f"Всего: {report['totalVulnerabilities']}\n\n"
    
    if report['vulnerabilities']:
        text += '-' * 60 + '\n'
        text += 'НАЙДЕННЫЕ УЯЗВИМОСТИ\n'
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
    print("""
    ╔══════════════════════════════════════════╗
    ║     SWILL Security Scanner              ║
    ║     GitHub: kektola70-sketch/.-exe-for-hacks ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Получение URL
    target = None
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    elif 'TARGET_URL' in os.environ:
        target = os.environ['TARGET_URL']
    elif 'INPUT_TARGET_URL' in os.environ:
        target = os.environ['INPUT_TARGET_URL']
    
    if not target:
        print("URL не указан")
        print("Использование: python scanner.py <URL>")
        print("Или установите переменную TARGET_URL")
        return
        
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target
        
    print(f"Цель: {target}")
    print()
    
    # Запуск сканирования
    scanner = SecurityScanner(target)
    report = scanner.run_full_scan()
    
    # Генерация отчетов
    text_report = generate_text_report(report)
    
    # Сохранение отчетов
    with open('security_report.txt', 'w', encoding='utf-8') as f:
        f.write(text_report)
        
    with open('security_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    print(f"\nОтчет сохранен: security_report.txt")
    print(f"JSON сохранен: security_report.json")
    print(f"\nОценка безопасности: {report['score']}/100")
    
    # Вывод отчета
    print("\n" + text_report)
    
    # Для GitHub Actions
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"score={report['score']}\n")
            f.write(f"critical={report['criticalCount']}\n")
            f.write(f"high={report['highCount']}\n")
            f.write(f"total={report['totalVulnerabilities']}\n")
            
    if 'GITHUB_ENV' in os.environ:
        with open(os.environ['GITHUB_ENV'], 'a') as f:
            f.write(f"SCAN_SCORE={report['score']}\n")
            f.write(f"SCAN_CRITICAL={report['criticalCount']}\n")


if __name__ == '__main__':
    main()
