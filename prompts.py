SYSTEM_PROMPT = ""

try:
    import json
    from pathlib import Path

    PROMPTS_FILE = Path(__file__).parent / "prompts.json"
    if PROMPTS_FILE.exists():
        with open(PROMPTS_FILE, "r", encoding="utf-8") as f:
            DATA = json.load(f)
            SYSTEM_PROMPT = DATA.get("system", "")
except Exception:
    SYSTEM_PROMPT = ""
