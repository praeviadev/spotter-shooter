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

### Bring-your-own Elastic hunting lab

Spotter-Shooter is designed to connect to an operator-controlled Elastic/Kibana lab. The public repository does **not** connect to any private hosted telemetry system by default.

For the internal evaluation demo, the platform was tested against an Elastic lab containing over **3.2 million searchable security events** from BOTSv3, APT29, APT3, LSASS campaigns, Log4Shell, and Golden SAML/ADFS datasets. External users should import those datasets into their own Elastic instance or point the deployment wizard at an existing lab they control.

Agents query whichever Elastic endpoint and index patterns the operator configures during deployment. This keeps private data private and makes the project reproducible in air-gapped or customer-controlled environments.

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

## Visual walkthrough

The screenshots below are intended to make the value of Spotter-Shooter obvious at a glance. Add image files under `docs/screenshots/` using the filenames shown below, and GitHub will render the walkthrough automatically.

### 1. Deployment Console — mission readiness

![Deployment health check](docs/screenshots/deployment-health.png)

Spotter-Shooter opens with a deployment console instead of a generic dashboard. The first screen gives the operator an immediate readiness check across the supporting services required for an AI-assisted hunt: Postgres, Redis, Elastic, Qdrant, MinIO, model routing, and worker processes.

This matters because the platform is designed for controlled security operations. Before the hunt begins, the operator can verify that the mission stack is healthy and that the system is ready to ingest documents, query telemetry, run agents, and preserve analyst decisions.

**Suggested capture:** the first deployment page with all services showing online.

---

### 2. Elastic telemetry connection — proof of real data

![Elastic telemetry test](docs/screenshots/elastic-telemetry-test.png)

The telemetry test is one of the most important screenshots. It shows that Spotter-Shooter is not just displaying static UI cards; it is connected to a live Elastic lab with over **3.2 million searchable security events**.

The current lab includes BOTSv3, APT29, APT3, LSASS campaign telemetry, Log4Shell, and Golden SAML/ADFS data. This gives the demo realistic volume, noise, and adversary-emulation evidence for measuring analyst-vs-agent performance.

**Suggested capture:** the Elastic connection result showing `3,237,839` total documents and the loaded indices.

---

### 3. Agent selection — modular hunting capability

![Agent selection](docs/screenshots/agent-selection.png)

Spotter-Shooter uses a modular agent model. Operators can start with default network-focused agents, then add host-focused agents when they have enough operational context to evaluate process, authentication, and account behavior.

This distinction is important: host-based AI observations should be treated as leads requiring analyst validation, not final determinations. The product is designed to preserve that professional analyst-in-the-loop workflow.

**Suggested capture:** the agent selection step showing Tier 1 network agents and Tier 2 host agents.

---

### 4. Hunt launch — from setup to active operation

![Launch hunt](docs/screenshots/launch-hunt.png)

The launch overlay marks the transition from configuration to active hunt. At this point, selected agents begin querying telemetry, producing findings, and preparing leads for analyst triage.

This gives supervisors a clean mental model: deploy the mission, connect the data, choose the agents, then launch the hunt.

**Suggested capture:** the launch overlay with the hunt marked active.

---

### 5. Analyst View — evidence-backed finding detail

![Analyst finding detail](docs/screenshots/analyst-finding-detail.png)

Analyst View is where agent output becomes operationally useful. Each finding includes a severity, explanation, key fields, matching event count, model attribution, raw evidence, and a recommended next question.

For the APT29 evaluation data, a strong screenshot is the rundll32/script execution finding. It demonstrates that the platform can surface a concrete adversary-emulation artifact and explain why it matters without hiding the evidence from the analyst.

**Suggested capture:** an APT29 finding with `Model: openai/gpt-4o-mini`, matching events, agent explanation, and recommended next question visible.

---

### 6. Raw log evidence — grounded, not generic

![Raw log sample](docs/screenshots/raw-log-sample.png)

The raw log panel is critical for credibility. Spotter-Shooter should not ask analysts to trust a generated paragraph. The analyst needs to see the underlying event sample and decide whether the agent's interpretation is justified.

This screenshot helps communicate the core product philosophy: AI accelerates triage, but evidence remains visible and reviewable.

**Suggested capture:** the same Analyst View finding with the raw log sample expanded.

---

### 7. Escalation — turning a lead into a case

![Escalation result](docs/screenshots/escalation-result.png)

When an analyst validates a finding, they can escalate it into a case. This creates a clean handoff from agent-generated lead to human-reviewed operational work.

This is the “shooter” side of Spotter-Shooter: agents spot the opportunity, but the analyst makes the decision to escalate, dismiss, or continue pivoting.

**Suggested capture:** a finding after escalation with the created case visible in the active cases drawer.

---

### 8. Commander View — leadership visibility

![Commander overview](docs/screenshots/commander-overview.png)

Commander View gives leaders a concise operational picture without forcing them into raw logs. It shows ASOM-style progress, active cases, agent activity, and events grouped by agent.

This view is designed for supervisors, team leads, and incident commanders who need to understand what the team knows, what is still uncertain, and where analyst attention is going.

**Suggested capture:** Commander View showing ASOM lines, agent activity feed, and events by agent.

---

### 9. Agent Admin — managing the hunting team

![Agent admin](docs/screenshots/agent-admin.png)

The admin panel shows that Spotter-Shooter is an agent framework, not a fixed demo. Operators can view built-in agents, see status and event counts, create custom agents, test them against Elastic, enable or disable them, and archive agents that are no longer needed.

This is especially useful for adapting the platform to a specific mission, environment, or supervisor-directed hunt objective.

**Suggested capture:** `/admin/agents` showing built-in agent statuses and the custom-agent creation/test controls.

---

### 10. Kibana dataset view — independent verification

![Kibana dataset view](docs/screenshots/kibana-dataset-view.png)

A Kibana screenshot helps independently prove the lab's scale. It shows that the platform is backed by realistic data volume rather than a tiny curated demo set.

For analyst-vs-agent comparisons, this is important context: both human analysts and agents are being evaluated against large, noisy telemetry, not a handful of hand-picked events.

**Suggested capture:** Kibana Discover, data views, or index list showing `botsv3-raw`, `apt29-endpoint`, `apt29-zeek`, and related indices.

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

## Elastic data model

The recommended model is **bring your own Elastic**.

Why this is better than shipping a preloaded Elastic stack in the default deployment:

- BOTSv3 and APT datasets are large; automatic import can take significant time, disk, and memory.
- Some environments need air-gapped or customer-controlled data handling.
- Public users should never be pointed at a maintainer's private lab.
- Teams can compare analysts and agents against their own telemetry or against locally imported public datasets.

For convenience, this repository includes evaluation guides for APT29 and BOTSv3, but the dataset import is intentionally an operator-controlled setup step rather than an automatic connection to a hosted lab.

---

## SSH forwarding demo mode

The demo deployment can be bound to server loopback only. It does not need to be publicly served.

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
