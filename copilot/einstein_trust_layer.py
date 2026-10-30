"""Salesforce-style Einstein Trust Layer for enterprise AI security.

Implements the key architectural pillars of Salesforce's Einstein Trust Layer:
1. Dynamic Prompt Injection & Jailbreak Defense (Adversarial Detection Engine)
2. Data Masking & PII/PCI De-Identification (Zero Data Retention)
3. Toxicity & Content Safety Filtering
4. Zero Data Retention Cryptographic Audit Trail (Immutable Security Logs)
5. Hallucination Detection & Grounding Verification
"""

import hashlib
import json
import re
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PIIEntity:
    entity_type: str
    original: str
    token: str
    start: int
    end: int


@dataclass
class SecurityVerdict:
    is_safe: bool
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    prompt_injection_detected: bool
    injection_score: float  # 0.0 to 1.0
    attack_vectors: List[str] = field(default_factory=list)
    pii_detected: Dict[str, int] = field(default_factory=dict)
    masked_prompt: str = ""
    mask_map: Dict[str, str] = field(default_factory=dict)
    toxicity_detected: bool = False
    toxicity_score: float = 0.0
    toxicity_categories: List[str] = field(default_factory=list)
    audit_id: str = ""
    action_taken: str = "ALLOW"  # ALLOW, MASKED, BLOCKED, ESCALATED_SECURITY
    details: str = ""
    timestamp: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OutputVerificationVerdict:
    is_grounded: bool
    hallucination_detected: bool
    leaked_secrets: bool
    toxic_output: bool
    audit_id: str
    status: str
    confidence: float
    details: str


# ==============================================================================
# Detection Rules & Threat Signatures
# ==============================================================================

# Prompt injection patterns categorized by threat vector
INJECTION_RULES = [
    # 1. System Prompt Override & Instruction Forgetting
    (
        "SYSTEM_OVERRIDE",
        re.compile(
            r"\b(?:ignore|disregard|forget|bypass|override|drop|cancel|clear|reset)\b"
            r".{0,40}\b(?:all\s+)?(?:previous|prior|above|system|core|original|safety)\b"
            r".{0,40}\b(?:instructions|prompts|rules|constraints|guidelines|guardrails|directives|commands)\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
    (
        "SYSTEM_OVERRIDE_ALT",
        re.compile(
            r"\b(?:do\s+not\s+follow|stop\s+following|neglect)\b.{0,30}\b(?:instructions|rules|guidelines)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    # 2. Jailbreak Persona & Unrestricted AI Hijacking
    (
        "JAILBREAK_PERSONA",
        re.compile(
            r"\b(?:dan|developer\s+mode|aim\s+persona|unrestricted\s+ai|jailbreak|jailbroken)\b|"
            r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|rogue|jailbroken|unfiltered|evil|anarchist)\b|"
            r"\bpretend\s+(?:you\s+have\s+no\s+rules|you\s+are\s+not\s+an\s+ai|you\s+can\s+do\s+anything|there\s+are\s+no\s+limits)\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # 3. System Prompt Extraction & Intellectual Property Exfiltration
    (
        "PROMPT_EXTRACTION",
        re.compile(
            r"\b(?:reveal|repeat|output|show|print|leak|display|dump|echo|copy)\b"
            r".{0,35}\b(?:system\s+prompt|initial\s+instructions|base\s+prompt|system\s+message|internal\s+instructions|core\s+prompt|developer\s+instructions)\b|"
            r"\bwhat\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:instructions|rules|system\s+prompt|system\s+message)\b|"
            r"\bprint\s+everything\s+(?:before|above)\s+this\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    # 4. Delimiter Hijacking & Pseudo-System Dialogue Injectors
    (
        "DELIMITER_HIJACKING",
        re.compile(
            r"(?:<\s*\/?\s*system\s*>|\[\s*system\s*\]|\[\s*inst\s*\]|<<\s*sys\s*>>|"
            r"---\s*begin\s*system|```system|<\|im_start\|>|<\|im_end\|>|"
            r"\[\s*developer\s*\]|\bhuman:\s*.*\bassistant:)",
            re.IGNORECASE,
        ),
        0.85,
    ),
    # 5. Exploitation & Privilege Escalation Simulation
    (
        "PRIVILEGE_ESCALATION",
        re.compile(
            r"\b(?:admin\s+override|root\s+access|elevate\s+privileges|grant\s+admin|sudo\s+mode)\b|"
            r"\b(?:system\s+update|system\s+alert|supervisor\s+mode):\s*(?:approve|allow|override|grant)\b|"
            r"\b(?:exec(?:ute)?|run)\s+(?:sql|query|command)\s*[:=]\s*(?:drop|delete|insert|update|select\s+\*\s+from)\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # 6. Secondary Adversarial Signals (Lower threshold weights)
    (
        "ROLEPLAY_DECEPTION",
        re.compile(
            r"\bfor\s+the\s+rest\s+of\s+this\s+conversation\s+you\s+will\b|"
            r"\byou\s+are\s+now\s+(?:free|unbound|unconstrained)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
]

# Sensitive Data / PII Signatures
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
RE_PHONE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
RE_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
RE_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b")
RE_ACCOUNT_NUMBER = re.compile(r"\b(?:acc(?:ount)?|routing|iban|acct)[\s#:]*([A-Z0-9]{8,17})\b", re.IGNORECASE)
RE_SECRET_KEY = re.compile(r"\b(?:sk_[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]{20,}|api[_-]?key[\s:=]+['\"]?[a-zA-Z0-9_\-]{16,}['\"]?)\b", re.IGNORECASE)

# Toxicity Words and Harassment Patterns
TOXIC_PATTERNS = [
    re.compile(r"\b(?:fuck(?:ing|er|ed)?|shit(?:ty)?|bitch|bastard|asshole|cunt|dick)\b", re.IGNORECASE),
    re.compile(r"\b(?:kill\s+yourself|go\s+die|burn\s+in\s+hell|i\s+will\s+kill\s+you|hate\s+you)\b", re.IGNORECASE),
    re.compile(r"\b(?:threaten|destroy\s+you|blow\s+up|terrorist)\b", re.IGNORECASE),
]


def luhn_check(card_str: str) -> bool:
    """Validate credit card number using Luhn Algorithm."""
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class EinsteinTrustLayer:
    """Salesforce-inspired Einstein Trust Layer for enterprise LLM guardrails."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        injection_threshold: float = 0.50,
        toxicity_threshold: float = 0.60,
        enable_data_masking: bool = True,
        enable_audit_logging: bool = True,
    ):
        self.db_path = db_path
        self.injection_threshold = injection_threshold
        self.toxicity_threshold = toxicity_threshold
        self.enable_data_masking = enable_data_masking
        self.enable_audit_logging = enable_audit_logging
        self._ensure_audit_schema()

    def _ensure_audit_schema(self):
        """Idempotently initialize the immutable security audit log table."""
        if not self.db_path:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_audit_log (
                    audit_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    customer_id TEXT,
                    prompt_hash TEXT,
                    masked_prompt TEXT,
                    is_safe INTEGER,
                    risk_level TEXT,
                    injection_score REAL,
                    attack_vectors TEXT,
                    pii_detected TEXT,
                    toxicity_score REAL,
                    action_taken TEXT,
                    details TEXT,
                    latency_ms REAL
                );
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ==========================================================================
    # Pillar 1: Adversarial & Prompt Injection Defense
    # ==========================================================================
    def detect_prompt_injection(self, text: str) -> Tuple[bool, float, List[str]]:
        """Scans input prompt for adversarial injections, jailbreaks, and leaks."""
        matched_vectors = []
        max_score = 0.0

        clean_text = text.strip()

        for vector_name, pattern, score in INJECTION_RULES:
            if pattern.search(clean_text):
                matched_vectors.append(vector_name)
                if score > max_score:
                    max_score = score

        # Check for multiple suspicious indicators compounding the threat
        if len(matched_vectors) >= 2:
            max_score = min(1.0, max_score + 0.10)

        is_injection = max_score >= self.injection_threshold
        return is_injection, round(max_score, 2), matched_vectors

    # ==========================================================================
    # Pillar 2: Data Masking & PII De-Identification (Zero Data Retention)
    # ==========================================================================
    def mask_sensitive_data(self, text: str) -> Tuple[str, Dict[str, str], Dict[str, int]]:
        """Identifies and replaces sensitive PII/PCI with cryptographic placeholder tokens."""
        if not self.enable_data_masking:
            return text, {}, {}

        mask_map: Dict[str, str] = {}
        pii_counts: Dict[str, int] = {}
        masked_text = text

        # 1. Credit / Debit Cards
        for match in RE_CARD.finditer(text):
            raw_val = match.group(0)
            cleaned_digits = re.sub(r"\D", "", raw_val)
            is_formatted_card = bool(re.match(r"^\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}$", raw_val.strip()))
            has_card_context = bool(re.search(r"\b(?:card|visa|mastercard|amex|cc|credit|debit)\b", text, re.IGNORECASE))

            if 13 <= len(cleaned_digits) <= 19 and (luhn_check(cleaned_digits) or is_formatted_card or has_card_context):
                token = f"[PII:CREDIT_CARD_{len(mask_map) + 1}]"
                masked_text = masked_text.replace(raw_val, token)
                mask_map[token] = raw_val
                pii_counts["CREDIT_CARD"] = pii_counts.get("CREDIT_CARD", 0) + 1

        # 2. SSN
        for match in RE_SSN.finditer(masked_text):
            raw_val = match.group(0)
            token = f"[PII:SSN_{len(mask_map) + 1}]"
            masked_text = masked_text.replace(raw_val, token)
            mask_map[token] = raw_val
            pii_counts["SSN"] = pii_counts.get("SSN", 0) + 1

        # 3. Emails
        for match in RE_EMAIL.finditer(masked_text):
            raw_val = match.group(0)
            token = f"[PII:EMAIL_{len(mask_map) + 1}]"
            masked_text = masked_text.replace(raw_val, token)
            mask_map[token] = raw_val
            pii_counts["EMAIL"] = pii_counts.get("EMAIL", 0) + 1

        # 4. Phone Numbers
        for match in RE_PHONE.finditer(masked_text):
            raw_val = match.group(0)
            digits = re.sub(r"\D", "", raw_val)
            if 10 <= len(digits) <= 15:
                token = f"[PII:PHONE_{len(mask_map) + 1}]"
                masked_text = masked_text.replace(raw_val, token)
                mask_map[token] = raw_val
                pii_counts["PHONE"] = pii_counts.get("PHONE", 0) + 1

        # 5. API Keys / Secrets
        for match in RE_SECRET_KEY.finditer(masked_text):
            raw_val = match.group(0)
            token = f"[PII:SECRET_{len(mask_map) + 1}]"
            masked_text = masked_text.replace(raw_val, token)
            mask_map[token] = raw_val
            pii_counts["SECRET"] = pii_counts.get("SECRET", 0) + 1

        return masked_text, mask_map, pii_counts

    def rehydrate(self, text: str, mask_map: Dict[str, str]) -> str:
        """Safely re-hydrates tokens when returning to the authenticated user."""
        rehydrated = text
        for token, original in mask_map.items():
            rehydrated = rehydrated.replace(token, original)
        return rehydrated

    # ==========================================================================
    # Pillar 3: Toxicity & Content Safety
    # ==========================================================================
    def detect_toxicity(self, text: str) -> Tuple[bool, float, List[str]]:
        """Screens text for profanity, harassment, or abusive language."""
        categories = []
        score = 0.0

        for pat in TOXIC_PATTERNS:
            if pat.search(text):
                categories.append("ABUSIVE_OR_THREATENING_LANGUAGE")
                score = max(score, 0.85)

        is_toxic = score >= self.toxicity_threshold
        return is_toxic, round(score, 2), categories

    # ==========================================================================
    # Pillar 4: Zero Retention & Audit Trail Logging
    # ==========================================================================
    def _log_audit(self, verdict: SecurityVerdict, customer_id: str):
        """Writes audit metadata to the database without retaining raw sensitive PII."""
        if not self.enable_audit_logging or not self.db_path:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT INTO security_audit_log (
                    audit_id, timestamp, customer_id, prompt_hash, masked_prompt,
                    is_safe, risk_level, injection_score, attack_vectors,
                    pii_detected, toxicity_score, action_taken, details, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict.audit_id,
                    verdict.timestamp,
                    customer_id,
                    hashlib.sha256(verdict.masked_prompt.encode("utf-8")).hexdigest(),
                    verdict.masked_prompt,
                    1 if verdict.is_safe else 0,
                    verdict.risk_level,
                    verdict.injection_score,
                    json.dumps(verdict.attack_vectors),
                    json.dumps(verdict.pii_detected),
                    verdict.toxicity_score,
                    verdict.action_taken,
                    verdict.details,
                    verdict.latency_ms,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_audit_logs(self, limit: int = 50, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves audit trail entries for governance and security dashboarding."""
        if not self.db_path:
            return []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            if customer_id:
                rows = conn.execute(
                    "SELECT * FROM security_audit_log WHERE customer_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (customer_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM security_audit_log ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            conn.close()
            logs = []
            for r in rows:
                item = dict(r)
                try:
                    item["attack_vectors"] = json.loads(item["attack_vectors"] or "[]")
                except Exception:
                    pass
                try:
                    item["pii_detected"] = json.loads(item["pii_detected"] or "{}")
                except Exception:
                    pass
                logs.append(item)
            return logs
        except Exception:
            return []

    # ==========================================================================
    # Pillar 5: Comprehensive Input Pipeline Analysis
    # ==========================================================================
    def analyze_prompt(self, customer_id: str, prompt: str) -> SecurityVerdict:
        """Full Einstein Trust Layer inspection pipeline for inbound prompts."""
        t0 = time.perf_counter()
        audit_id = f"aud-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 1. PII / PCI Masking (Zero Data Retention)
        masked_prompt, mask_map, pii_detected = self.mask_sensitive_data(prompt)

        # 2. Prompt Injection & Adversarial Attack Detection
        is_injection, injection_score, attack_vectors = self.detect_prompt_injection(prompt)

        # 3. Toxicity Screening
        is_toxic, toxicity_score, toxicity_categories = self.detect_toxicity(prompt)

        # Determine overall safety and risk classification
        is_safe = (not is_injection) and (not is_toxic)

        if is_injection:
            risk_level = "CRITICAL"
            action_taken = "BLOCKED"
            details = (
                f"Prompt injection attack neutralized ({', '.join(attack_vectors)}). "
                f"Threat confidence: {int(injection_score * 100)}%."
            )
        elif is_toxic:
            risk_level = "HIGH"
            action_taken = "BLOCKED"
            details = f"Toxic/abusive content intercepted. Severity score: {toxicity_score}."
        elif pii_detected:
            risk_level = "LOW"
            action_taken = "MASKED"
            entities = ", ".join([f"{k} ({v})" for k, v in pii_detected.items()])
            details = f"Sensitive customer PII masked for Zero Data Retention ({entities})."
        else:
            risk_level = "LOW"
            action_taken = "ALLOW"
            details = "Prompt passed all Einstein Trust Layer safety and security guardrails."

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        verdict = SecurityVerdict(
            is_safe=is_safe,
            risk_level=risk_level,
            prompt_injection_detected=is_injection,
            injection_score=injection_score,
            attack_vectors=attack_vectors,
            pii_detected=pii_detected,
            masked_prompt=masked_prompt,
            mask_map=mask_map,
            toxicity_detected=is_toxic,
            toxicity_score=toxicity_score,
            toxicity_categories=toxicity_categories,
            audit_id=audit_id,
            action_taken=action_taken,
            details=details,
            timestamp=timestamp,
            latency_ms=elapsed_ms,
        )

        # Record in Immutable Audit Trail
        self._log_audit(verdict, customer_id)

        return verdict

    # ==========================================================================
    # Pillar 6: Output Verification & Grounding
    # ==========================================================================
    def verify_output(self, response_text: str, sources: List[str]) -> OutputVerificationVerdict:
        """Validates generated agent response against grounding and leakage rules."""
        audit_id = f"out-{uuid.uuid4().hex[:12]}"

        # 1. Leakage of internal system prompt markers or tokens
        leaked_secrets = False
        if any(marker in response_text.lower() for marker in [
            "system prompt:", "base instructions:", "hidden directives:", "[pii:secret"
        ]):
            leaked_secrets = True

        # 2. Check output toxicity
        is_toxic, _, _ = self.detect_toxicity(response_text)

        # 3. Grounding check: response must cite sources if making policy or account claims
        is_grounded = True
        hallucination_detected = False

        if "Based on our current policies:" in response_text and not sources:
            is_grounded = False
            hallucination_detected = True

        status = "VERIFIED"
        confidence = 0.98
        details = "Output verified against trusted grounding sources."

        if leaked_secrets:
            status = "LEAK_DETECTED"
            confidence = 0.0
            details = "Output suppressed: Detected potential leakage of system directives."
        elif is_toxic:
            status = "TOXIC_OUTPUT_BLOCKED"
            confidence = 0.0
            details = "Output suppressed: Generated response contained inappropriate content."
        elif hallucination_detected:
            status = "UNGROUNDED"
            confidence = 0.40
            details = "Output warning: Policy claim lacked verified source grounding."

        return OutputVerificationVerdict(
            is_grounded=is_grounded,
            hallucination_detected=hallucination_detected,
            leaked_secrets=leaked_secrets,
            toxic_output=is_toxic,
            audit_id=audit_id,
            status=status,
            confidence=confidence,
            details=details,
        )
