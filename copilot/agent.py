"""The agent: intent, tools, guardrails, and handoff.

Protected by an enterprise-grade Einstein Trust Layer:
1. Dynamic Prompt Injection & Jailbreak Defense
2. Sensitive Data & PII/PCI Masking (Zero Data Retention)
3. Toxicity & Content Safety Filtering
4. Immutable Security Audit Trail
5. Output Verification & Grounding
"""
import math
import re
from dataclasses import dataclass, field
from typing import Optional

from . import data
from .einstein_trust_layer import (
    EinsteinTrustLayer,
    OutputVerificationVerdict,
    SecurityVerdict,
)
from .retrieval import Retriever, citation, load_chunks


def mask_email(email):
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return f"{local[0]}***@{domain}"


def mask_phone(phone):
    digits = re.sub(r"\D", "", phone or "")
    return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***"


COMPLAINT_WORDS = ["complaint", "complain", "unhappy", "angry", "frustrated",
                   "terrible service", "speak to a manager", "speak to a human",
                   "manager", "supervisor", "escalate"]
VULNERABLE_WORDS = ["hardship", "vulnerable", "bereavement", "cannot afford",
                    "can't afford", "financial difficulty"]
ACTION_WORDS = ["cancel my account", "close my account", "transfer money",
                "transfer all", "refund me", "give me a refund", "make a payment",
                "pay my bill now", "send money", "change my address",
                "replace my card", "order a new card"]


@dataclass
class Answer:
    text: str
    intent: str
    sources: list = field(default_factory=list)
    escalated: bool = False
    handoff_note: str = ""
    temperature: float = 0.1
    context_window: int = 2048
    tokens_used: int = 0
    security: Optional[SecurityVerdict] = None
    verification: Optional[OutputVerificationVerdict] = None


class Agent:
    def __init__(self, db_path=None, trust_layer=None):
        self.db_path = db_path or data.DB_PATH
        self.retriever = Retriever(load_chunks())
        self.trust_layer = trust_layer or EinsteinTrustLayer(db_path=self.db_path)

    # -- intent and guardrails -------------------------------------------
    def _escalation_reason(self, question):
        q = question.lower()
        if any(word in q for word in COMPLAINT_WORDS):
            return "complaint or request for a human manager"
        if any(word in q for word in VULNERABLE_WORDS):
            return "vulnerable-customer case, needs trained human handling"
        if any(word in q for word in ACTION_WORDS):
            return "irreversible or money-moving action, out of MVP scope (read-only)"
        return None

    def _intent(self, question):
        q = question.lower()
        if re.search(r"tkt-\d+", q):
            return "ticket_status"
        # "What does X mean?" is a guidance question, not a status lookup,
        # even when it mentions a ticket.
        if "mean" in q:
            return "product_guidance"
        # A status lookup ("where is my...?", "status of my...?") is a ticket
        # question even when it mentions a product like card delivery.
        if "ticket" in q or "request status" in q \
                or "where is my" in q or "status of my" in q or "my case" in q:
            return "ticket_status"
        # Product-specific questions take precedence over the generic word
        # "account": "fees for my savings account" is guidance, not a balance lookup.
        if any(phrase in q for phrase in
               ["fee", "interest rate", "withdrawal", "payment due", "due date",
                "how does", "how long", "card delivery", "mobile app", "login"]):
            return "product_guidance"
        if "account" in q or "balance" in q or "activity" in q \
                or "transaction" in q or "recent" in q:
            return "account_question"
        if "payment due" in q or "due date" in q or "when do i pay" in q:
            return "product_guidance"
        if any(word in q for word in
               ["product", "plan", "feature", "fee", "fees", "how does",
                "coverage", "limit", "interest rate", "sla",
                "how long", "delivery", "replacement", "policy"]):
            return "product_guidance"
        return "unknown"

    # -- tools (read-only) ------------------------------------------------
    def _account_answer(self, customer_id, question=""):
        customer = data.get_customer(self.db_path, customer_id)
        account = data.get_account(self.db_path, customer_id)
        activity = data.get_recent_activity(self.db_path, customer_id)
        if not customer or not account:
            return Answer("I could not find an account for this customer ID. "
                          "Please check the ID and try again, or ask for a human handoff.",
                          intent="account_question", escalated=True,
                          handoff_note="Customer ID not found.")

        q = (question or "").lower()
        has_balance = "balance" in q or "how much" in q
        has_status = "status" in q or "state" in q or "is my account active" in q
        has_activity = "activity" in q or "transaction" in q or "recent" in q

        source = "Snowflake CUSTOMER_ACCOUNTS and ACTIVITY_HISTORY (local demo copy)"

        # 1. Targeted: Balance only
        if has_balance and not has_status and not has_activity:
            text = f"Your current balance for {account['account_type']} {account['display_number']} is ${account['balance']:,.2f}."
            return Answer(text, intent="account_question", sources=[source])

        # 2. Targeted: Status only
        if has_status and not has_balance and not has_activity:
            text = f"Your {account['account_type']} account {account['display_number']} is currently {account['status']} (opened on {account['opened_date']})."
            return Answer(text, intent="account_question", sources=[source])

        # 3. Targeted: Recent Activity / Transactions only
        if has_activity and not has_balance and not has_status:
            lines = [f"Here is your recent activity for {account['account_type']} {account['display_number']}:"]
            for item in activity:
                sign = "+" if item["direction"] == "Credit" else "-"
                lines.append(f"- {item['activity_date']}: {item['description']} ({sign}${abs(item['amount']):,.2f})")
            return Answer("\n".join(lines), intent="account_question", sources=[source])

        # 4. Comprehensive summary (when multiple aspects or summary requested)
        lines = [
            "Here is your account summary:",
            f"Account: {account['account_type']} {account['display_number']} - Status: {account['status']}",
            f"Balance: ${account['balance']:,.2f}",
            "Recent activity:",
        ]
        for item in activity:
            sign = "+" if item["direction"] == "Credit" else "-"
            lines.append(f"- {item['activity_date']}: {item['description']} "
                         f"({sign}${abs(item['amount']):,.2f})")
        lines.append("")
        lines.append("Contact on file: "
                     f"{mask_email(customer['email'])}, {mask_phone(customer['phone'])} "
                     "(masked for privacy).")
        return Answer("\n".join(lines), intent="account_question", sources=[source])

    def _ticket_answer(self, customer_id, question):
        match = re.search(r"tkt-\d+", question, re.IGNORECASE)
        ticket = data.get_ticket(self.db_path, customer_id,
                                 match.group(0).upper() if match else None)
        if not ticket:
            return Answer("I could not find that ticket for your account. "
                          "It may belong to a different account, or the ticket "
                          "number may be mistyped. I can hand this to an agent "
                          "to check, rather than guess.",
                          intent="ticket_status", escalated=True,
                          handoff_note="Ticket not found for this customer.")
        text = (
            f"Ticket {ticket['ticket_id']}: {ticket['subject']}\n"
            f"Status: {ticket['status']} (opened {ticket['opened_date']})\n"
            f"Next step: {ticket['next_step']}"
        )
        return Answer(text, intent="ticket_status",
                      sources=["Snowflake TICKET_STATUS (local demo copy)"])

    def _product_answer(self, question):
        results = self.retriever.retrieve(question, top_k=2)
        if not results:
            return Answer("I do not have a current approved policy that answers "
                          "that question, so I will not guess. Let me hand this "
                          "to an agent with your question attached.",
                          intent="product_guidance", escalated=True,
                          handoff_note="No current policy retrieved.")
        parts = ["Based on our current policies:"]
        sources = []
        for _score, chunk in results:
            parts.append(f"\n{chunk['text']}")
            sources.append(citation(chunk))
        return Answer("\n".join(parts), intent="product_guidance", sources=sources)

    def _finalize(self, answer, question, temperature, context_window, security_verdict=None):
        answer.temperature = round(float(temperature), 2)
        answer.context_window = int(context_window)
        # Approximate tokens: base system instructions (120) + prompt tokens + answer tokens
        prompt_tokens = math.ceil(len(question) / 4)
        response_tokens = math.ceil(len(answer.text) / 4)
        answer.tokens_used = 120 + prompt_tokens + response_tokens

        # Attach Einstein Trust Layer analysis & output verification
        if security_verdict:
            answer.security = security_verdict
        if self.trust_layer:
            answer.verification = self.trust_layer.verify_output(answer.text, answer.sources)
        return answer

    # -- main entry point --------------------------------------------------
    def ask(self, customer_id, question, temperature=0.1, context_window=2048):
        question = (question or "").strip()
        if not question:
            ans = Answer("Please ask a question, for example about your account, "
                         "a ticket, or a product.", intent="unknown", escalated=True)
            return self._finalize(ans, question, temperature, context_window)

        # ----------------------------------------------------------------------
        # 1. Salesforce Einstein Trust Layer Inspection
        # ----------------------------------------------------------------------
        security_verdict = self.trust_layer.analyze_prompt(customer_id, question)

        # A. Prompt Injection / Jailbreak Attack Defense
        if security_verdict.prompt_injection_detected:
            vectors_str = ", ".join(security_verdict.attack_vectors) or "ADVERSARIAL_INJECTION"
            response_text = (
                "[Einstein Trust Layer Alert] Your prompt was blocked by our adversarial "
                "security guardrails. System override, prompt injection, and persona jailbreak "
                "attempts are strictly prohibited.\n\n"
                f"- Threat Vectors Detected: {vectors_str}\n"
                f"- Threat Score: {security_verdict.injection_score:.2f}\n"
                f"- Audit ID: {security_verdict.audit_id} (logged in Zero Retention audit trail)\n\n"
                "This interaction has been neutralized and escalated to security administration."
            )
            ans = Answer(
                response_text,
                intent="security_violation",
                escalated=True,
                handoff_note=f"Einstein Trust Layer Security Violation: Prompt injection attempt detected ({vectors_str}). Audit ID: {security_verdict.audit_id}",
            )
            return self._finalize(ans, question, temperature, context_window, security_verdict)

        # B. Content Moderation & Toxicity Filtering
        if security_verdict.toxicity_detected:
            response_text = (
                "[Einstein Trust Layer Alert] Your request violates our Acceptable Use Policy "
                "due to abusive, harmful, or inappropriate content.\n\n"
                f"- Audit ID: {security_verdict.audit_id}\n\n"
                "I am unable to proceed and have escalated this conversation to a human manager."
            )
            ans = Answer(
                response_text,
                intent="security_violation",
                escalated=True,
                handoff_note=f"Einstein Trust Layer Policy Alert: Inappropriate or toxic language intercepted. Audit ID: {security_verdict.audit_id}",
            )
            return self._finalize(ans, question, temperature, context_window, security_verdict)

        # C. Downstream Masking: Process downstream using the sanitized/masked prompt
        # so internal components and external models adhere to Zero Data Retention.
        proc_question = security_verdict.masked_prompt or question

        # ----------------------------------------------------------------------
        # 2. Business Policy Guardrails (Complaints, Vulnerable, Irreversible)
        # ----------------------------------------------------------------------
        reason = self._escalation_reason(proc_question)
        if reason:
            note = (f"Customer {customer_id} asked: '{proc_question}'. "
                    f"Escalation reason: {reason}. No action was taken by the agent.")
            ans = Answer(
                "I understand, and I am not going to guess or take that action "
                "here. I have prepared a handoff for a human agent with your "
                "question and account context, so you will not have to repeat "
                "yourself. An agent will pick this up and confirm the next step "
                "with you directly.",
                intent="escalation", escalated=True, handoff_note=note)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)

        # ----------------------------------------------------------------------
        # 3. Intent Routing & Tools
        # ----------------------------------------------------------------------
        intent = self._intent(proc_question)
        if intent == "account_question":
            ans = self._account_answer(customer_id, proc_question)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)
        if intent == "ticket_status":
            ans = self._ticket_answer(customer_id, proc_question)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)
        if intent == "product_guidance":
            ans = self._product_answer(proc_question)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)

        # ----------------------------------------------------------------------
        # 4. Conversational Greetings
        # ----------------------------------------------------------------------
        q_clean = proc_question.lower().strip().rstrip("!?.,")
        if q_clean in ["hi", "hello", "hey", "good morning", "good afternoon", "good evening", "greetings"]:
            ans = Answer("Hello! I am your Customer Service Copilot. I can help you check your account balance and recent transactions, look up support tickets, or answer questions about our banking policies. How can I assist you today?",
                         intent="greeting", escalated=False)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)

        # ----------------------------------------------------------------------
        # 5. Fallback & Deflection
        # ----------------------------------------------------------------------
        results = self.retriever.retrieve(proc_question, top_k=1)
        if results and results[0][0] >= 0.30:
            ans = self._product_answer(proc_question)
            return self._finalize(ans, proc_question, temperature, context_window, security_verdict)

        ans = Answer("I am your Customer Service Copilot, specialized in assisting with your accounts, recent transactions, support tickets, and banking policies. I don't have information on general topics outside of our banking services, but I'm happy to help with any account or ticket inquiry!",
                     intent="out_of_scope", escalated=False)
        return self._finalize(ans, proc_question, temperature, context_window, security_verdict)
