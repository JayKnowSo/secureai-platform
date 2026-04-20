"""
SecureAI Platform — LLM Scanner Tests
=======================================
TDD proof for OWASP LLM Top 10 detection.

Four checks:
  LLM01 — Prompt Injection
  LLM02 — Insecure Output Handling
  LLM06 — PII in Prompts
  LLM08 — Excessive Agency
"""

from secureai.scanners.llm_scanner import LLMScanner


class TestLLMScanner:

    # ── CLEAN CODE ───────────────────────────────────────────────────

    def test_clean_llm_code_passes(self, tmp_path):
        """
        Safe LLM code with static prompts and no dangerous output handling
        must produce zero findings — no false positives.
        """
        pyfile = tmp_path / "safe_llm.py"
        pyfile.write_text("""
import os
import anthropic

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

prompt = "Summarize the following security documentation:"
response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": prompt}]
)
result = response.content[0].text
print(result)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        assert len(findings) == 0, (
            f"Clean LLM code produced findings: {findings}"
        )

    # ── LLM01: PROMPT INJECTION ──────────────────────────────────────

    def test_prompt_injection_fstring_detected(self, tmp_path):
        """
        LLM01: User input concatenated into prompt via f-string must be flagged HIGH.
        Attackers can override system instructions through unsanitized input.
        """
        pyfile = tmp_path / "vulnerable.py"
        pyfile.write_text("""
user_input = request.json()['message']
prompt = f"Answer this question: {user_input}"
response = client.messages.create(model="claude-sonnet-4-6", messages=[{"role":"user","content":prompt}])
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM01" in ids, (
            "f-string with user_input in prompt should trigger LLM01"
        )

    def test_prompt_injection_concatenation_detected(self, tmp_path):
        """
        LLM01: String concatenation of user_query into prompt must be flagged.
        """
        pyfile = tmp_path / "vulnerable.py"
        pyfile.write_text("""
user_query = get_user_input()
prompt = "Translate this text: " + user_query
response = llm.complete(prompt)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM01" in ids, (
            "String concatenation of user_query into prompt should trigger LLM01"
        )

    def test_static_prompt_not_flagged(self, tmp_path):
        """
        LLM01: A fully static prompt string must never be flagged.
        """
        pyfile = tmp_path / "safe.py"
        pyfile.write_text("""
prompt = "List the top 5 OWASP vulnerabilities."
response = client.complete(prompt)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        lm01 = [f for f in findings if f["id"] == "LLM01"]
        assert len(lm01) == 0, (
            "Static prompt should not trigger LLM01"
        )

    # ── LLM02: INSECURE OUTPUT HANDLING ─────────────────────────────

    def test_eval_on_llm_response_detected(self, tmp_path):
        """
        LLM02: Passing LLM response directly to eval() must be CRITICAL.
        Attackers can inject arbitrary Python code through the model output.
        """
        pyfile = tmp_path / "dangerous.py"
        pyfile.write_text("""
response = client.messages.create(model="claude-sonnet-4-6", messages=[...])
result = response.content[0].text
eval(result)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM02" in ids, (
            "eval(result) where result is LLM output should trigger LLM02"
        )

    def test_exec_on_llm_output_detected(self, tmp_path):
        """
        LLM02: exec() on LLM output must be flagged as CRITICAL.
        """
        pyfile = tmp_path / "dangerous.py"
        pyfile.write_text("""
llm_response = get_llm_response(prompt)
exec(llm_response)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM02" in ids, (
            "exec(llm_response) should trigger LLM02"
        )

    def test_os_system_on_llm_output_detected(self, tmp_path):
        """
        LLM02: os.system() called with LLM output must be CRITICAL.
        """
        pyfile = tmp_path / "dangerous.py"
        pyfile.write_text("""
import os
ai_response = call_model(prompt)
os.system(ai_response)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM02" in ids, (
            "os.system(ai_response) should trigger LLM02"
        )

    def test_print_of_llm_output_not_flagged(self, tmp_path):
        """
        LLM02: Simply printing LLM output is safe — must not be flagged.
        """
        pyfile = tmp_path / "safe.py"
        pyfile.write_text("""
result = client.complete(prompt)
print(result)
log.info(result)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        lm02 = [f for f in findings if f["id"] == "LLM02"]
        assert len(lm02) == 0, (
            "Printing LLM output should not trigger LLM02"
        )

    # ── LLM06: PII IN PROMPTS ────────────────────────────────────────

    def test_ssn_in_prompt_detected(self, tmp_path):
        """
        LLM06: SSN embedded in prompt construction must be flagged HIGH.
        Sending PII to external LLM APIs may violate HIPAA/GDPR.
        """
        pyfile = tmp_path / "pii_leak.py"
        pyfile.write_text("""
prompt = f"Analyze this patient record: SSN={ssn}, name={patient_name}"
response = client.complete(prompt)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM06" in ids, (
            "SSN in prompt f-string should trigger LLM06"
        )

    def test_dob_in_prompt_detected(self, tmp_path):
        """
        LLM06: date_of_birth variable in prompt must be flagged HIGH.
        """
        pyfile = tmp_path / "pii_leak.py"
        pyfile.write_text("""
prompt = "Patient details: " + str(dob) + " credit_card=" + str(credit_card)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM06" in ids, (
            "dob/credit_card in prompt concatenation should trigger LLM06"
        )

    def test_non_pii_variables_not_flagged(self, tmp_path):
        """
        LLM06: Normal variable names in prompts must not be flagged.
        """
        pyfile = tmp_path / "safe.py"
        pyfile.write_text("""
document = load_document(doc_id)
prompt = f"Summarize this document: {document}"
response = client.complete(prompt)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        lm06 = [f for f in findings if f["id"] == "LLM06"]
        assert len(lm06) == 0, (
            "Non-PII variables in prompts should not trigger LLM06"
        )

    # ── LLM08: EXCESSIVE AGENCY ──────────────────────────────────────

    def test_http_request_from_llm_output_detected(self, tmp_path):
        """
        LLM08: HTTP request triggered directly from LLM output must be CRITICAL.
        LLM can be manipulated to exfiltrate data or trigger unintended actions.
        """
        pyfile = tmp_path / "excessive_agency.py"
        pyfile.write_text("""
import requests
ai_response = call_llm(prompt)
requests.post(ai_response, data=payload)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM08" in ids, (
            "requests.post(ai_response) should trigger LLM08"
        )

    def test_file_open_from_llm_output_detected(self, tmp_path):
        """
        LLM08: open() called with LLM response as path must be flagged CRITICAL.
        """
        pyfile = tmp_path / "excessive_agency.py"
        pyfile.write_text("""
llm_response = get_model_output(prompt)
with open(llm_response, 'w') as f:
    f.write(data)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        ids = [f["id"] for f in findings]
        assert "LLM08" in ids, (
            "open(llm_response) should trigger LLM08"
        )

    def test_safe_file_open_not_flagged(self, tmp_path):
        """
        LLM08: open() with a static path or config variable must not be flagged.
        """
        pyfile = tmp_path / "safe.py"
        pyfile.write_text("""
output_path = config.get("output_path")
with open(output_path, 'w') as f:
    f.write(result)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()

        lm08 = [f for f in findings if f["id"] == "LLM08"]
        assert len(lm08) == 0, (
            "open() with static config path should not trigger LLM08"
        )

    # ── EDGE CASES ───────────────────────────────────────────────────

    def test_empty_directory_no_crash(self, tmp_path):
        """Scanner must not crash on an empty directory."""
        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert findings == []

    def test_venv_directory_skipped(self, tmp_path):
        """
        .venv directory must be skipped — third-party libraries
        may contain patterns that trigger false positives.
        """
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        venv_file = venv_dir / "dangerous.py"
        venv_file.write_text("""
user_input = "test"
prompt = f"test {user_input}"
eval(result)
        """)

        scanner = LLMScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert len(findings) == 0, (
            ".venv directory should be skipped entirely"
        )
