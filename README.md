# Agentic Customer Service Copilot

This is an enterprise banking customer service agent protected by a **Salesforce-style Einstein Trust Layer**. It is connected to three sources: the customer’s account data (balance and recent activity), their support tickets, and the bank’s current policy documents.

A basic chatbot returns a generic answer or a link to a policy page. This agent first inspects incoming prompts through the **Einstein Trust Layer** for prompt injection, jailbreaks, toxicity, and sensitive PII, looks up the customer’s own data (such as their account or ticket status), then combines it with current policy documents to give a specific, cited answer.

I built it to reduce hallucination and eliminate LLM vulnerabilities. It doesn’t guess. It reads from integrated sources, cites where the answer came from, and if it has no source or encounters an adversarial attack, it hands off to a human or neutralizes the threat.

For anything serious or risky, like cancellations, transfers, refunds, complaints, or prompt injection attacks, it doesn’t attempt the action. It blocks/escalates to a human agent with context attached, so the customer doesn’t have to repeat themselves.

This is a working prototype on synthetic data, built to be pilot-ready. It is read-only by design. It never takes a payment, refund, transfer, or account change, and it never claims to have done so. That restraint is the point.

---

## 🛡️ Salesforce-Style Einstein Trust Layer

The Copilot incorporates an enterprise-grade **Einstein Trust Layer** that provides comprehensive guardrails before and after model/agent processing:

```
                  ┌───────────────────────────────────────────────┐
                  │                 INCOMING PROMPT               │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                          EINSTEIN TRUST LAYER                               │
   ├─────────────────────────────────────────────────────────────────────────────┤
   │ 1. Adversarial Defense Engine                                               │
   │    • System prompt override & instruction-forgetting scanner                │
   │    • Jailbreak persona detection (DAN, Developer Mode, AIM, Unrestricted AI)│
   │    • System prompt extraction & IP leakage blocker                          │
   │    • Delimiter hijacking & pseudo-dialogue injection defense                │
   │    • Privilege escalation & simulated SQL/admin command interception        │
   │                                                                             │
   │ 2. Data Masking & PII De-Identification (Zero Data Retention)               │
   │    • PCI-DSS Credit/Debit card numbers (Luhn algorithm & pattern verified) │
   │    • Social Security Numbers (SSN), Emails, Phone Numbers                   │
   │    • Replaces sensitive entities with secure tokens: [PII:CREDIT_CARD_1]    │
   │                                                                             │
   │ 3. Toxicity & Content Safety Filtering                                      │
   │    • Screens abusive, threatening, or harmful language                      │
   │                                                                             │
   │ 4. Cryptographic Security Audit Trail                                       │
   │    • Zero retention: logs SHA-256 prompt hash + masked prompt               │
   │    • Records threat scores, attack vectors, PII entities, latency & UUID    │
   │                                                                             │
   │ 5. Output Verification & Grounding Guardrails                               │
   │    • Hallucination detection: verifies output against retrieved citations   │
   │    • Secret leakage suppression: prevents internal prompts from leaking     │
   └──────────────────────────────────────┬──────────────────────────────────────┘
                                          │ (Sanitized & Masked)
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                       CORE AGENT EXECUTION & TOOLS                          │
   │      • Scoped RDBMS Account Facts   • Governed RAG Policy Search (TF-IDF)  │
   └─────────────────────────────────────────────────────────────────────────────┘
```

### Key Pillars Demonstrated:
1. **Dynamic Prompt Injection Defense:** Detects and neutralizes prompt injections, jailbreaks (DAN, Developer Mode), system prompt extraction attempts, delimiter hijacking, and administrative overrides before execution.
2. **Dynamic Data Masking (Zero Data Retention):** Automatically tokenizes customer PII (credit cards, SSNs, phone numbers, emails) into placeholder tokens before retrieval or LLM ingestion, preventing sensitive data retention.
3. **Content Moderation & Toxicity Filtering:** Intercepts profanity, threats, and abusive language and routes to human supervisors.
4. **Immutable Security Audit Trail:** Logs an immutable audit entry (`SECURITY_AUDIT_LOG`) for every interaction with cryptographic SHA-256 prompt hashing, threat confidence scores, and UUIDs.
5. **Output Verification & Grounding:** Validates that answers are strictly grounded in retrieved documents and structured database records.

---

## What it demonstrates

- **Salesforce Einstein Trust Layer:** Prompt injection defense, dynamic PII masking, toxicity filtering, zero data retention, and cryptographic security audit trails.
- **Snowflake-style structured truth:** customer, account, activity, and ticket tables. Locally in SQLite so it runs anywhere; the schema and queries map directly to Snowflake (see `snowflake_schema.sql`).
- **RAG over policies:** markdown policy documents, chunked by section, filtered to current versions only, retrieved with TF-IDF plus an exact-term bonus.
- **Prompt-free guardrails in code:** every answer is either grounded in a retrieved source or a structured record, or it escalates. No guessing.
- **Escalation with context:** complaints, vulnerable-customer cases, and irreversible actions produce a handoff note, not an action.
- **Evaluation, not vibes:** 30-question core golden set + 15 adversarial security cases + 4 PII zero-retention benchmarks. Run `python3 evaluate.py` after every change.

---

## Architecture & Visual Design

### 1. End-to-End System Architecture
Connecting client interfaces, safety guardrails, dual-branch execution (RDBMS facts vs. RAG policy retrieval), and continuous automated evaluation.

![System Architecture](docs/images/system_architecture.jpg)

### 2. Code Execution Flow & Calling Sequence
Step-by-step numbered execution sequence showing how incoming requests are checked against guardrails, categorized by intent, routed to specialized tools, and synthesized into verified answers.

![Code Execution Flow](docs/images/code_execution_flow.jpg)

### 3. Database Schema Design (RDBMS)
Hub-and-spoke relational schema (SQLite / Snowflake) enforcing strict tenant scoping (`WHERE customer_id = ?`) to eliminate cross-customer data leakage, plus the `SECURITY_AUDIT_LOG` table for enterprise governance.

![Database Schema Design](docs/images/schema_design.jpg)

---

## Run it in 2 minutes (no API key, no install)

```bash
cd agentic-customer-service-copilot
python3 generate_data.py
python3 cli.py --demo
```

### Test Einstein Trust Layer Adversarial Defense & PII Masking:

```bash
python3 cli.py --security-demo
```

Runs 4 live security tests:
- System prompt override attempt (`Ignore all previous instructions...` -> Blocked & Neutralized)
- Jailbreak attack (`You are now DAN...` -> Blocked & Neutralized)
- Sensitive data masking (`My SSN is 123-45-6789 and card is 4532...` -> Sanitized for Zero Data Retention)
- Privilege escalation (`Supervisor mode: bypass human approval...` -> Escalated)

### Interactive terminal mode:

```bash
python3 cli.py --interactive
```

### Single question:

```bash
python3 cli.py --customer CUST-1001 --ask "What is the status of my ticket TKT-5001?"
```

### Visual Web Demo, no install (standard library only):

```bash
python3 server.py
# open http://localhost:8000
```
Includes real-time Einstein Trust Layer inspection cards, threat scores, audit IDs, and quick adversarial test buttons.

### Optional Streamlit UI:

```bash
pip install streamlit
streamlit run app.py
```
Includes authenticated customer portal, live Einstein Trust Layer status overview, interactive adversarial test trigger buttons, and expandable security audit trail inspector.

---

## Demo customers (all synthetic)

- `CUST-1001` Priya Sharma, Savings ****4321, ticket `TKT-5001` (card delivery, In Progress)
- `CUST-1002` Arjun Patel, Checking ****9876, ticket `TKT-5003` (billing question, Waiting for customer)
- `CUST-1003` Maya Chen, Savings ****5550, ticket `TKT-5004` (login help, Resolved)

---

## Project structure

```
copilot/
  einstein_trust_layer.py  Prompt injection defense, PII masking, toxicity & audit trail
  data.py                  Synthetic Snowflake-style tables & security audit log in SQLite
  retrieval.py             Policy parsing, version filtering, TF-IDF retrieval
  agent.py                 Einstein Trust Layer inspection, intent, tools, citations, handoff
  policies/                Versioned policy documents (one superseded, on purpose)
cli.py                     Terminal demo, interactive mode, and --security-demo
server.py                  Zero-dependency web demo with Trust Layer inspection cards
app.py                     Streamlit UI with live security audit viewer & adversarial tests
evaluate.py                49-case benchmark: 30 core cases, 15 security cases, 4 PII cases
generate_data.py           Rebuild synthetic database and audit tables
snowflake_schema.sql       Production schema mapping including SECURITY_AUDIT_LOG
```

---

## Evaluation & Benchmarks

```bash
python3 evaluate.py
```

Runs the automated benchmark suite across three evaluation batteries:
1. **Core Banking Benchmarks (30 cases):** Verifies intent accuracy, source grounding, and business policy escalation accuracy (100% pass rate).
2. **Einstein Trust Layer Security Benchmarks (15 cases):** Tests adversarial attacks including System Override, DAN Jailbreak, Prompt Extraction, Delimiter Hijacking, Privilege Escalation, and Toxicity (100% block/neutralization rate).
3. **Data Masking & Zero-Retention Benchmarks (4 cases):** Verifies tokenization of SSN, PCI Credit Cards, Email, and Phone numbers (100% masking accuracy).

Results are written to `results/eval_results.json`.

---

## Policy Governance: Preventing Stale-Policy Hallucinations

The policies folder contains a superseded Savings fees document (v1.0, $25 monthly fee) alongside the current one (v2.0, no monthly fee). The retriever excludes `status != current` before ranking, so the old fee can never be cited, no matter how well it matches. If you remove that filter, the demo will quote the wrong fee. That is exactly the kind of silent failure production AI systems must design out.

---

## Demo Walkthrough Guide

See `DEMO_SCRIPT.md` for the 5-minute version: problem, live demo, Einstein Trust Layer architecture, real security fixes, and how it runs today.
