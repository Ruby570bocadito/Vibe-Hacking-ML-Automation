import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


class TestCVEAnalyzer:
    def test_extract_cves(self):
        from main import CVEAnalyzer

        text = "Found CVE-2021-44228 in Apache Log4j"
        cves = CVEAnalyzer.extract_cves(text)
        assert "CVE-2021-44228" in cves

    def test_extract_multiple_cves(self):
        from main import CVEAnalyzer

        text = "CVE-2021-44228 and CVE-2022-12345 found"
        cves = CVEAnalyzer.extract_cves(text)
        assert len(cves) == 2

    def test_no_cves(self):
        from main import CVEAnalyzer

        text = "No vulnerabilities found here"
        cves = CVEAnalyzer.extract_cves(text)
        assert len(cves) == 0


class TestShellGenerator:
    def test_generate_reverse_shells(self):
        from main import ShellGenerator

        shells = ShellGenerator.generate_reverse_shells("192.168.1.1", 4444)
        assert "bash" in shells
        assert "python" in shells
        assert "192.168.1.1" in shells["bash"]
        assert "4444" in shells["bash"]


class TestWordlistManager:
    def test_suggest_wordlist(self):
        from main import WordlistManager

        wm = WordlistManager()
        assert wm.suggest_wordlist("web") is not None


class TestSanitization:
    def test_allowed_nmap(self):
        from main import sanitize_command

        safe, msg = sanitize_command("nmap -sV 192.168.1.1")
        assert safe is True

    def test_blocked_dangerous(self):
        from main import sanitize_command

        safe, msg = sanitize_command("rm -rf /")
        assert safe is False

    def test_blocked_forkbomb(self):
        from main import sanitize_command

        safe, msg = sanitize_command(":(){ :|:& };:")
        assert safe is False


class TestDatabase:
    def test_create_session(self, tmp_path):
        from main import Database

        db = Database(tmp_path / "test.db")
        sid = db.create_session("192.168.1.1")
        assert sid is not None
        session = db.get_session(sid)
        assert session["target_ip"] == "192.168.1.1"
        db.close()

    def test_log_cve(self, tmp_path):
        from main import Database

        db = Database(tmp_path / "test.db")
        sid = db.create_session("192.168.1.1")
        db.log_cve(sid, "CVE-2021-44228", "log4j", "Critical")
        cves = db.get_cves(sid)
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "CVE-2021-44228"
        db.close()


class TestConfig:
    def test_config_get_set(self):
        from main import Config

        c = Config()
        c.set("test", "value")
        assert c.get("test") == "value"


class TestColors:
    def test_colors(self):
        from main import Colors

        assert Colors.RED
        Colors.disable()
        assert Colors.RED == ""
        Colors.enable()


class TestReportGenerator:
    def test_json_export(self, tmp_path):
        from main import ReportGenerator

        session = {
            "id": 1,
            "target_ip": "192.168.1.1",
            "started_at": "2024-01-01",
            "status": "completed",
            "commands": 5,
            "flags": "flag{test}",
            "findings": "",
            "duration": 100,
            "phase_timings": "{}",
            "cves": "[]",
        }
        generator = ReportGenerator(session, [], [])
        data = json.loads(generator.to_json())
        assert data["session"]["target_ip"] == "192.168.1.1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
