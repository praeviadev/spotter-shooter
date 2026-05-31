# Spotter-Shooter

**Spotter-Shooter is an AI-assisted threat hunting operations console for professional security teams.**

It is built around a simple operational idea: let autonomous hunting agents act as *spotters* across large telemetry sets, then let human analysts act as *shooters* who validate, dismiss, escalate, and brief leadership.

The goal is not to replace analysts. The goal is to compress the time between **massive log volume** and **actionable, evidence-backed leads**.

---

## Why this matters

Modern security teams are buried under telemetry. A realistic hunt may involve millions of endpoint, network, identity, cloud, and application events. Analysts lose time on:

- forming the first useful query
- pivoting between datasets
- separating high-signal leads from noise
- writing findings in a clear operational format
- keeping commanders updated while triage is still underway

Spotter-Shooter gives the team an operator-focused workflow:

1. **Deploy / configure the mission**
2. **Connect telemetry**
3. **Select built-in or custom agents**
4. **Launch the hunt**
5. **Review agent findings in Analyst View**
6. **Escalate validated findings into cases**
7. **Brief leadership in Commander View**

---

## Current MVP capabilities

### Deployment console

A guided deployment workflow for mission setup:

- infrastructure health check
- mission document upload path
- Elastic telemetry test
- model provider test
- agent selection
- hunt launch

### Live Elastic-backed hunting

The MVP is wired to a local Elastic/Kibana hunting lab containing over **3.2 million searchable security events**:

- **BOTSv3:** 1,857,913 events
- **APT29 / MITRE ATT&CK evaluation:** 791,171 events
- **LSASS campaign telemetry:** 364,466 events
- **APT3:** 223,563 events
- **Log4Shell:** 674 events
- **Golden SAML / ADFS:** 52 events

Agents query real indexed telemetry, not only frontend mock cards.

### OpenRouter-backed agent summaries

Agent findings are summarized through OpenRouter-backed LLM calls. Findings include:

- title
- severity
- explanation
- key fields
- matched event counts
- raw log sample
- recommended next question
- confidence
- model used

### Analyst View

The analyst console is designed for triage:

- view agent findings
- filter by severity
- inspect raw evidence
- review agent rationale
- dismiss weak findings
- escalate validated findings

### Commander View

The commander console gives leadership a high-level operational picture:

- active findings
- agent activity feed
- ASOM-style progress lines
- threat actor / attribution notes
- cases and escalation state
- event counts by agent

### Agent administration

The admin panel supports agent lifecycle management:

- view built-in agent status
- view custom agent status
- see event counts by agent
- create custom agents
- test custom agents against Elastic
- enable / disable custom agents
- archive custom agents

---

## Built-in agent roster

Spotter-Shooter includes 11 built-in agents.

### Tier 1: default network agents

- New Domain Agent
- New External IP Agent
- DGA Agent
- Beaconing Agent
- JA3/JA4 Agent
- Threat Intel Correlation Agent
- ASOM Drafting Agent

### Tier 2: optional host agents

- Sysmon Process Anomaly Agent
- Windows Logon Anomaly Agent
- PowerShell Activity Agent
- Service Account Activity Agent

Host-based observations are intentionally advisory. Process behavior, authentication patterns, and account activity still require analyst review and environment-specific context.

---

## Demo value proposition

Spotter-Shooter is meant to demonstrate a measurable analyst-augmentation loop:

### Before

An analyst starts with millions of logs and must manually decide where to begin.

### After

Agents generate initial evidence-backed leads, and the analyst spends time validating and escalating instead of searching blindly.

### What to measure

- Time to first useful lead
- Time to first validated pivot
- Number of accepted findings
- Number of false positives
- Analyst confidence
- Commander briefing quality
- Final incident narrative quality

---

## Suggested screenshots for the README

Add screenshots under `docs/screenshots/` and reference them in this README.

Recommended screenshots:

1. **Deployment Console — Health Check**
   - Shows the tactical UI and stack readiness.
   - Capture the first page with Postgres, Redis, Elastic, Qdrant, MinIO, LiteLLM, and worker status.

2. **Elastic Telemetry Test**
   - Show successful Elastic connection with `3,237,839` total docs and the loaded indices.
   - This proves the platform is connected to real hunting data.

3. **Agent Selection Screen**
   - Show Tier 1 network agents and Tier 2 host agents.
   - Good for communicating that this is a modular agent framework, not a single chatbot.

4. **Launch Hunt Overlay**
   - Capture the moment the hunt becomes active.
   - This is a strong visual for presentations.

5. **Analyst View — Finding Detail**
   - Select a finding such as APT29 rundll32/script execution.
   - Make sure the screenshot includes:
     - agent explanation
     - key fields
     - matching events
     - model used: `openai/gpt-4o-mini`
     - recommended next question

6. **Raw Log Sample Expanded**
   - Show the raw evidence panel open.
   - This helps prove the agent is grounded in telemetry, not just writing generic text.

7. **Escalation Result**
   - Show a finding after clicking Escalate.
   - Include the created case in the active cases drawer.

8. **Commander View**
   - Show ASOM lines, agent feed, and events by agent.
   - This screenshot sells leadership visibility.

9. **Agent Admin Panel**
   - Show built-in agents with enabled/disabled status and event counts.
   - If comfortable, show a custom agent test result.

10. **Kibana Dataset View**
    - Show Kibana Discover or index/data view list with BOTSv3/APT29 indices.
    - This reinforces that the demo is backed by realistic data volume.

Example markdown once screenshots are added:

```md
![Deployment health check](docs/screenshots/deployment-health.png)
![Elastic telemetry test](docs/screenshots/elastic-telemetry-test.png)
![Analyst finding detail](docs/screenshots/analyst-finding-detail.png)
![Commander overview](docs/screenshots/commander-overview.png)
```

---

## Analyst-vs-agent evaluation docs

This repository includes two practical evaluation guides:

- [`docs/apt29-evaluation-guide.md`](docs/apt29-evaluation-guide.md)
- [`docs/botsv3-walkthrough.md`](docs/botsv3-walkthrough.md)

Use these to compare:

- human analyst hunt time
- agent time to first lead
- pivot quality
- false positive rate
- evidence quality
- final narrative quality

---

## SSH forwarding demo mode

This deployment is intentionally bound to server loopback only. It is not publicly served.

Forward the app from a workstation:

```bash
ssh -L 8097:127.0.0.1:8097 USER@SERVER_IP
```

Then open:

```text
http://127.0.0.1:8097
```

Useful demo routes:

```text
http://127.0.0.1:8097/
http://127.0.0.1:8097/operations.html?view=analyst
http://127.0.0.1:8097/operations.html?view=commander
http://127.0.0.1:8097/admin/agents
```

---

## Quick start

```bash
./deploy.sh
```

Health check:

```bash
curl http://127.0.0.1:8097/api/health
```

Agent status:

```bash
curl http://127.0.0.1:8097/api/agents
```

Launch a hunt:

```bash
curl -X POST http://127.0.0.1:8097/api/setup/launch \
  -H 'Content-Type: application/json' \
  -d '{}'
```

---

## Status

This is an MVP/prototype intended for evaluation, demos, and controlled analyst-vs-agent experiments. It is not yet a hardened production SOC platform.

Current focus:

- prove value on realistic security datasets
- measure agent acceleration against human analysts
- improve custom agent authoring
- improve evidence-grounded reporting
- reduce false positives through analyst feedback
