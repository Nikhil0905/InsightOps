# 🔮 Future Scope — InsightOps

InsightOps v1.0 was intentionally designed to be **stable, deterministic, and SOC-assist only**.  
Future work focuses on **maturity and resilience**, not feature bloat or automation hype.

The following enhancements are **deliberate, scoped, and production-aligned**.

---

## 1️⃣ Signal Health & Telemetry Assurance (High Priority)

One of the most important future additions is expanding the **Signal Health Check**.

Planned enhancements:
- Track last-event timestamps per critical sourcetype
- Detect log ingestion gaps and forwarder failures
- Flag silent data loss as a first-class incident
- Surface warnings like:
  - ⚠️ `linux_secure`: no events in last 10 minutes  
  - ⚠️ `wineventlog:security`: lagging by 6 minutes

**Why this matters**

A SOC that cannot detect its own blindness is operationally unsafe.  
Detection coverage is meaningless if telemetry silently fails.

---

## 2️⃣ Analyst Feedback (Only After Platform Guarantees)

Analyst feedback was intentionally **removed in v1** due to reliability risks.

Future reintroduction is possible **only if**:
- Writes are guaranteed (no UI-token ambiguity)
- Schema is immutable and audited
- Feedback never retroactively changes incidents
- Weight updates are transparent and versioned

**Lesson applied**

A broken feedback loop is worse than no feedback loop.  
This feature will only return when correctness is provable.

---

## 3️⃣ Adaptive Scoring (Still Deterministic)

Future versions may support:
- Time-decay–based risk scoring
- Environment-aware host criticality
- Analyst-defined risk multipliers (config-only)

What will **not** be added:
- Black-box ML scoring
- Probabilistic risk without explanation

**Principle**

Explainability and trust remain non-negotiable.

---

## 4️⃣ SOAR Integration (Read-Only Intelligence Feed)

InsightOps may integrate with SOAR platforms in a **strictly advisory role**:
- Provide enriched incident context
- Supply recommended investigation steps
- Never trigger actions automatically

This keeps InsightOps aligned with its SOC-assist philosophy.

---

## 5️⃣ Detection Coverage Expansion (Controlled)

Future detections may include:
- Cloud identity abuse (Azure AD / AWS IAM)
- Linux kernel-level persistence
- Insider threat behavioral patterns

All new detections must:
- Be MITRE-aligned
- Be testable via replay
- Integrate cleanly into correlation logic

---

## 6️⃣ Platform Hardening & Observability

Engineering-focused improvements:
- Structured logging for the AI engine
- Pipeline latency metrics
- Alert-to-incident processing SLAs
- Engine self-health reporting

These changes strengthen InsightOps as a **long-running SOC service**, not a script.

---

## 🚫 Explicitly Out of Scope (By Design)

InsightOps will **not** pursue:
- Autonomous response
- ML-first decision making
- UI-driven state mutation
- Alert suppression without explanation

These are conscious design exclusions to protect analyst trust.

---

## 🧠 Closing Thought

InsightOps is not built to impress with features.  
It is built to **protect decision integrity under pressure**.

Future work will only be accepted if it:
- Improves reliability
- Preserves explainability
- Respects SOC operational realities
