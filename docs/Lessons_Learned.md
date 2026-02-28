# 🧠 InsightOps — Lessons Learned

This document captures what I actually learned while building InsightOps — not what I planned, not what tutorials say, but what I figured out by breaking things, debugging for hours, and knowing when to stop.

Everything below is written from my perspective, based on the entire journey.

---

## 1. Splunk Is Event-Centric, Not UI-Centric

One of the first hard truths I encountered:

> **Splunk only cares about events. Not dashboards. Not metadata. Not UI state.**

I proved this myself:
- `| metadata type=sourcetypes` showed nothing
- `index=ai_feedback | stats count` clearly showed events

Metadata is not ground truth. If an event is indexed, Splunk works. If it's not, no dashboard trick will fix it.

**Takeaway:** Trust events. Verify with SPL, not the UI.

---

## 2. Dashboards Are for Viewing, Not Doing

This was the most painful lesson.

I tried everything: Simple XML submit buttons, token-based `collect`, conditional writes. In every case, dashboards **silently failed** — tokens resolved visually but searches didn't execute, and there were no error messages.

**Takeaway:** Dashboards are read-only surfaces. Any logic that mutates state belongs in the engine, not the UI.

---

## 3. Tokens Are Just String Substitution, Not Runtime Variables

I saw events indexed with literal strings like `$incident_id$` and `$verdict$`. That's when it clicked.

> Tokens exist at render time, not execution time.

Scheduled searches run as `nobody`, have no dashboard context, and indexed token strings verbatim.

**Takeaway:** Tokens are text replacement. Never rely on them for operational data flow.

---

## 4. `collect` Is Powerful — and Extremely Dangerous

`collect` worked perfectly in manual SPL, engine-driven writes, and controlled test injections. It failed silently in every dashboard-driven or tokenized context.

**Takeaway:** Only use `collect` where execution is **guaranteed and auditable** — in the engine, not the UI.

---

## 5. Analyst Feedback Loops Are Harder Than Detections

I thought detections would be the hardest part. They weren't.

The real complexity was audit defensibility, overwrite vs. append semantics, analyst accountability, and silent corruption risk. Writes silently failed. Tokens didn't resolve. Partial data polluted the index. Trust in the system degraded.

> **A broken feedback loop is worse than no feedback loop.**

**Takeaway:** If feedback is wrong, the AI pipeline becomes dangerous. I removed the feedback system entirely to protect integrity.

---

## 6. Knowing When to Kill a Feature Is Senior Engineering

I consciously chose to:
- Kill the feedback dashboard
- Accept Splunk platform limits
- Protect system integrity
- Prefer correctness over completeness

Not everything that can be built should be built.

**Takeaway:** Stopping a feature can be the most responsible engineering decision.

---

## 7. Deterministic Systems Build Trust

Throughout the project I deliberately avoided ML, probabilistic scoring, and black-box logic. Instead, I enforced deterministic weights, explainable bonuses, capped scores, and reproducible behavior.

Because everything was deterministic, I could explain every score, debug every incident, and justify every decision.

> **Explainability beats intelligence in SOC environments.**

**Takeaway:** In security, trust beats cleverness. Every time.

---

## 8. Correlation Is Where Alerts Become Incidents

There is a clear difference between:
- Isolated alerts → noise
- Correlated chains → meaning

When I built chains like Password Spraying → Kerberoasting → Lateral Movement → Privilege Escalation → Persistence → Ransomware Pre-Impact, that's when incidents felt *real*.

**Takeaway:** SOCs respond to attack narratives, not individual events.

---

## 9. Linux Logging Is Fragile and Easy to Kill

I didn't read this — I lived it. I personally stopped `rsyslog`, disabled services, vacuumed journals, rotated logs, and changed permissions. Result: searches stopped returning data, detections "broke", and the forwarder was healthy while the logs were gone.

**Takeaway:** Most broken detections are actually broken logging.

---

## 10. Keeping Everything in `index=main` Was a Smart Move

Using a single index reduced confusion, simplified SPL, made debugging faster, and avoided routing mistakes. Data was separated using `sourcetype` and `source` — not index proliferation.

**Takeaway:** Fewer indexes = faster reasoning. Separate with fields, not topology.

---

## 11. Detection Engineering Is Systems Engineering

I initially believed detection quality came from good SPL and correct thresholds. Reality proved otherwise. Detection quality actually depends on log availability, ingestion reliability, sourcetype correctness, time skew, and pipeline integrity.

**Takeaway:** Detection engineering is systems engineering, not just query writing.

---

## 12. Silent Systems Are the Most Dangerous

While working on detections, I realized:
- No alerts ≠ no attacks
- Silence does not mean safety
- Log stoppage is itself an incident

This realization directly led to the **Signal Health Check** feature.

**Takeaway:** A SOC must detect its own blindness. If logs stop and nobody notices, the SOC is already compromised — operationally.

---

## 13. Layer Separation Is Non-Negotiable

Without explicitly planning it, I converged to this architecture after breaking things repeatedly:

| Layer | Responsibility |
|---|---|
| Splunk Alerts | Signal generation only |
| Python Engine | Correlation & deterministic scoring |
| Explainability | Human-readable summaries & MITRE mapping |
| Dashboards | Visualization only |

**Takeaway:** Mixing UI, logic, and state mutation causes invisible corruption.

---

## 14. SOC-Assist ≠ SOC-Automation

InsightOps assists analysts, explains reasoning, and enriches incidents. It never responds automatically. This boundary is intentional and important.

> **Automation without perfect confidence is operational risk.**

**Takeaway:** Build the assist layer first. Automation earns its place through trust, not ambition.

---

## 15. Real Splunk Knowledge Comes from Breaking It

Documentation didn't teach me Splunk. Breaking it did:
- Execution contexts are strict
- UI ≠ backend
- Alerts ≠ events
- Scheduled ≠ interactive
- Silence ≠ success

**Takeaway:** Splunk mastery is earned through failure, not reading.

---

## 🧠 Final Reflection

By the end of InsightOps, I stopped thinking like:
> *"Someone building detections"*

And started thinking like:
> **A SOC architect protecting decision integrity.**

That mindset shift — not the code — is the real success of this project.