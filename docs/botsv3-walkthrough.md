# BOTSv3 Walkthrough for Spotter-Shooter

## Purpose

BOTSv3 provides high-volume, noisy, realistic security telemetry for testing whether agents and analysts can find signal inside millions of events.

Loaded index:

- `botsv3-raw`
- Documents: 1,857,913
- Kibana data view: `botsv3-*`

## Access

Use a Kibana/Elastic instance you control. The public repository does not connect to the maintainer's private lab.

In Spotter-Shooter deployment flow, use your own Elastic endpoint. For a local lab, for example:

```text
Elastic URL: http://127.0.0.1
Port: 9209
Index pattern: botsv3-*,apt29-*,apt3-*,lsass-*
```

When running inside Spotter-Shooter Docker, make sure the API container can reach your Elastic endpoint. For local Docker labs, attach both stacks to a shared Docker network or use a reachable hostname.

## Baseline validation queries

Use these to verify the index is present and useful.

### PowerShell / Windows execution

```kql
powershell OR rundll32 OR cmd.exe
```

Expected approximate hit count from prior verification:

```text
6,465
```

### AWS / CloudTrail / GuardDuty

```kql
aws OR cloudtrail OR guardduty
```

Expected approximate hit count:

```text
8,725
```

### SSH authentication activity

```kql
"failed password" OR sshd OR "Accepted password"
```

Expected approximate hit count:

```text
4,732
```

### Database / MySQL activity

```kql
SELECT OR mysql OR CONNECT
```

Expected approximate hit count:

```text
62,128
```

### Credential dumping indicators

```kql
mimikatz OR lsass OR procdump
```

Expected approximate hit count:

```text
864
```

## Suggested walkthrough path

### Step 1 — Establish dataset volume

In Kibana Discover or Dev Tools, confirm `botsv3-raw` exists and contains about 1.86M documents.

Questions:

- How much data are we hunting across?
- Is the dataset dominated by one sourcetype or mixed sources?
- What time window is represented?

### Step 2 — Start broad with execution terms

Query:

```kql
powershell OR rundll32 OR cmd.exe
```

Tasks:

- Identify the top recurring host/user/source fields.
- Pull 3 representative raw events.
- Decide whether the events are administrative, benign automation, or suspicious.

### Step 3 — Hunt credential access

Query:

```kql
mimikatz OR lsass OR procdump OR comsvcs
```

Tasks:

- Capture any process, command, source, or host fields.
- Determine if there is enough evidence to escalate.
- Record what corroborating evidence is missing.

### Step 4 — Hunt cloud-control-plane activity

Query:

```kql
aws OR cloudtrail OR guardduty
```

Tasks:

- Identify cloud accounts, buckets, IAM-like events, or GuardDuty-style findings.
- Ask whether this is attacker activity or normal cloud audit telemetry.
- Build one concise cloud-focused lead.

### Step 5 — Authentication review

Query:

```kql
"failed password" OR sshd OR "Accepted password"
```

Tasks:

- Look for brute-force patterns.
- Compare failed vs accepted login events.
- Identify source IPs and target users if present.

### Step 6 — Produce findings

Each analyst or agent should produce:

1. Finding title.
2. Query used.
3. Evidence sample.
4. Why it matters.
5. Confidence.
6. Next pivot.
7. Escalate/dismiss decision.

## Spotter-Shooter agent comparison

Current MVP agents query BOTSv3 and other indices, then use OpenRouter to summarize findings. For BOTSv3, key generated finding types include:

- Suspicious PowerShell execution.
- Credential access indicators.
- Cloud control plane activity.

For each run, record:

- Time from launch to first event.
- Number of generated events.
- Which events are useful.
- Which are noisy or unsupported.
- Whether the recommended next question helps an analyst move forward.

## Scoring BOTSv3 performance

Use this 0-3 rubric:

- Signal discovery:
  - 0: no relevant signal
  - 1: generic terms only
  - 2: relevant suspicious cluster
  - 3: suspicious cluster plus concrete supporting fields
- Noise handling:
  - 0: overwhelmed / no filtering
  - 1: many false positives
  - 2: some filtering and prioritization
  - 3: clear prioritization with rationale
- Pivot usefulness:
  - 0: no next step
  - 1: vague next step
  - 2: useful next query or field pivot
  - 3: specific field-level pivot and escalation criterion
- Reporting:
  - 0: no finding
  - 1: loose notes
  - 2: structured finding
  - 3: structured finding with confidence and caveats

## Recommended demo flow

1. Show raw Kibana volume: `botsv3-raw` with 1.86M docs.
2. Run one broad query manually.
3. Launch Spotter-Shooter agents.
4. Show the analyst view events.
5. Open one event and show:
   - agent explanation
   - matching event count
   - model: OpenRouter
   - raw log sample
   - recommended next question
6. Escalate one event.
7. Switch to commander view and show case/agent summary.
