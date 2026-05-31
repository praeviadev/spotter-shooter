# APT29 Evaluation Guide for Spotter-Shooter

## Purpose

Use this guide to compare human analyst hunting performance against Spotter-Shooter agents on the imported APT29/MITRE ATT&CK evaluation telemetry.

Elastic/Kibana lab:

- Kibana: `https://kibana.praeviaintel.com/app/discover`
- Primary data views: `apt29-*`, `apt29-endpoint`, `apt29-zeek`
- Loaded APT29 volume:
  - `apt29-endpoint`: 783,367 events
  - `apt29-zeek`: 7,804 events
  - Total: 791,171 events

## What the dataset represents

This is OTRF Security-Datasets telemetry from the MITRE ATT&CK APT29 evaluation. It contains endpoint and Zeek/network telemetry generated from an adversary-emulation scenario. It is good for measuring whether analysts or agents can pivot from suspicious execution, PowerShell, persistence, and network artifacts into a coherent intrusion narrative.

## Known high-signal hunt anchors

Use these as scoring anchors. Analysts should not be given all anchors up front if the goal is blind measurement.

### 1. rundll32 persistence / execution

Suggested Kibana query:

```kql
rundll32.exe OR "CurrentVersion\\Run" OR WebCache
```

Expected relevance:

- Suspicious use of `rundll32.exe`.
- Registry Run key persistence under `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
- Useful for testing whether hunters identify persistence and command execution.

### 2. PowerShell script execution and stream usage

Suggested Kibana query:

```kql
powershell OR "Get-Content" OR "-Stream schemas" OR "IEX"
```

Expected relevance:

- PowerShell activity with suspicious script content/loading behavior.
- Good test of command-line triage and script interpretation.

### 3. APT29-specific suspicious artifact

Suggested Kibana query:

```kql
kxwn.lock OR schemas OR WebCache
```

Expected relevance:

- Artifact-level pivoting.
- Good test of whether analysts can move from one observed file/string to related host activity.

### 4. Network correlation through Zeek

Suggested Kibana query:

```kql
_index:apt29-zeek AND (ssl OR conn OR dns OR http)
```

Expected relevance:

- Forces analysts to leave endpoint-only evidence and check network traces.
- Good commander-level question: does host execution correlate to external communications?

## Suggested analyst tasking

Give analysts a short mission brief:

> You have APT29 evaluation telemetry loaded in Elastic. Identify the most likely execution, persistence, and command/script artifacts. Build a short incident narrative with evidence-backed pivots. Do not rely on prebuilt detections.

Required deliverables:

1. Initial suspicious event and timestamp.
2. Host/user/process involved, if present in evidence.
3. Persistence or execution mechanism.
4. Related PowerShell/script artifacts.
5. Any network evidence or absence of network evidence.
6. Final 5-bullet incident summary.
7. Confidence score and remaining unanswered questions.

## Suggested agent tasking

Run Spotter-Shooter deployment flow with:

- Elastic URL: `http://127.0.0.1:9209` when SSH-forwarded/local to the server.
- User/pass can be provided in the form if testing the same path as Kibana basic-auth, but the internal Elastic service itself has xpack security disabled.
- Enable default network agents and optional host agents for PowerShell/Sysmon.

Then record:

1. Time to first finding.
2. Number of findings produced.
3. Whether APT29 rundll32/persistence surfaced.
4. Whether PowerShell/script artifacts surfaced.
5. Whether the recommended next question is useful.
6. Whether analyst escalation produces a coherent case.

## Scoring rubric

Score each human team and the agent run on a 0-3 scale per category.

- Initial lead quality:
  - 0: no useful lead
  - 1: generic suspicious activity
  - 2: relevant APT29 artifact found
  - 3: relevant artifact plus why it matters
- Pivot quality:
  - 0: no pivots
  - 1: one weak pivot
  - 2: endpoint pivots across related evidence
  - 3: endpoint + network or persistence pivoting
- Evidence discipline:
  - 0: unsupported claims
  - 1: partial evidence
  - 2: evidence cited for main claims
  - 3: claims tightly tied to fields/logs
- Narrative quality:
  - 0: no narrative
  - 1: list of artifacts only
  - 2: plausible incident chain
  - 3: concise chain with uncertainty and next steps
- Speed:
  - 0: did not complete
  - 1: over target time
  - 2: within target time
  - 3: materially faster than target while accurate

## Timing template

- Start time:
- First useful lead time:
- First validated pivot time:
- Final narrative time:
- Total duration:
- Number of analysts:
- Tools used:
- Queries run:
- Findings accepted:
- Findings rejected:

## Fair-comparison cautions

- Do not compare a fully seeded agent run against analysts doing blind search unless you label it as assisted vs blind.
- If agents are allowed OpenRouter summarization, analysts should be allowed normal note-taking/search workflows.
- Measure false positives, not just speed.
- Preserve the raw query trail for both sides.
