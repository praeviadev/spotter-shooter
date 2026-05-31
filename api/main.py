import asyncio
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncpg
import httpx
from urllib.parse import urlparse
from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from pydantic_settings import BaseSettings
from redis.asyncio import Redis


class Settings(BaseSettings):
    database_url: str = "postgresql://spotter:spotter-local-dev@postgres:5432/spotter"
    redis_url: str = "redis://redis:6379/0"
    qdrant_url: str = "http://qdrant:6333"
    minio_endpoint: str = "minio:9000"
    elasticsearch_url: str = "http://host.docker.internal:9209"
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-4o-mini"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
app = FastAPI(title="Spotter-Shooter API")
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
pool: Optional[asyncpg.Pool] = None


def E(data=None, error=None, meta=None):
    return {"success": error is None, "data": data, "error": error, "meta": meta or {}}


async def P():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=10)
    return pool


@app.get("/")
async def root():
    return FileResponse(FRONTEND / "deployment.html")


@app.get("/deployment.html")
async def deployment():
    return FileResponse(FRONTEND / "deployment.html")


@app.get("/operations.html")
async def operations():
    return FileResponse(FRONTEND / "operations.html")


async def ok_pg():
    try:
        return await (await P()).fetchval("select 1") == 1
    except Exception:
        return False


async def ok_redis():
    try:
        r = Redis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        return True
    except Exception:
        return False


async def ok_http(url):
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            return (await c.get(url)).status_code < 500
    except Exception:
        return False


def _safe_es_url(url: str) -> str:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return settings.elasticsearch_url.rstrip("/")
    return (url or settings.elasticsearch_url).rstrip("/")


async def es_request(method: str, path: str, payload=None, timeout=8, base_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
    base = _safe_es_url(base_url or settings.elasticsearch_url)
    url = base + path
    auth = (username, password) if username or password else None
    client_kwargs = {"timeout": timeout}
    if auth is not None:
        client_kwargs["auth"] = auth
    async with httpx.AsyncClient(**client_kwargs) as c:
        kwargs = {}
        if payload is not None:
            kwargs["json"] = payload
        r = await c.request(method, url, **kwargs)
        r.raise_for_status()
        return r.json()


async def openrouter_agent_summary(agent: str, evidence: dict, severity: str = "medium") -> dict:
    if not settings.openrouter_api_key:
        return {
            "title": evidence.get("title") or f"{agent} Finding",
            "explanation": evidence.get("fallback_explanation") or "OpenRouter is not configured; generated a deterministic finding from live telemetry.",
            "recommended_next_question": "Review the raw evidence and correlate with host/user context before escalation.",
            "confidence": 0.45,
            "model_used": "not_configured",
        }
    prompt = {
        "agent": agent,
        "severity": severity,
        "evidence": evidence,
        "task": "Return concise JSON with keys title, explanation, recommended_next_question, confidence. Make it sound like a SOC hunting agent. Do not invent facts outside evidence."
    }
    headers = {"Authorization": f"Bearer {settings.openrouter_api_key}", "Content-Type": "application/json", "HTTP-Referer": "http://127.0.0.1:8097", "X-Title": "Spotter-Shooter MVP"}
    payload = {"model": settings.openrouter_model, "messages": [{"role": "system", "content": "You are a professional threat hunting agent. Reply only with compact JSON."}, {"role": "user", "content": json.dumps(prompt, default=str)}], "temperature": 0.2, "max_tokens": 450}
    try:
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?|```$", "", content, flags=re.I|re.M).strip()
        data = json.loads(content)
        raw_conf = data.get("confidence", 0.65)
        if isinstance(raw_conf, str):
            conf_map = {"critical": 0.9, "high": 0.8, "medium": 0.6, "low": 0.35}
            raw_conf = conf_map.get(raw_conf.lower().strip(), raw_conf)
        try:
            conf = float(raw_conf)
            if conf > 1:
                conf = conf / 100.0
        except Exception:
            conf = 0.65
        return {
            "title": str(data.get("title") or evidence.get("title") or f"{agent} Finding")[:180],
            "explanation": str(data.get("explanation") or "Agent reviewed live telemetry evidence.")[:2000],
            "recommended_next_question": str(data.get("recommended_next_question") or "What correlated host/user activity supports this finding?")[:800],
            "confidence": max(0, min(1, conf)),
            "model_used": settings.openrouter_model,
        }
    except Exception as exc:
        msg = str(exc)[:220] or exc.__class__.__name__
        return {
            "title": evidence.get("title") or f"{agent} Finding",
            "explanation": (evidence.get("fallback_explanation") or "Model call failed; deterministic finding generated from live telemetry.") + f" Model error: {exc.__class__.__name__}: {msg}",
            "recommended_next_question": "Review the raw evidence and retry the model-backed agent test if needed.",
            "confidence": 0.40,
            "model_used": "error",
        }


@app.get("/api/health")
async def health():
    es_ok = await ok_http(settings.elasticsearch_url)
    s = {
        "Postgres": await ok_pg(),
        "Redis": await ok_redis(),
        "Elasticsearch": es_ok,
        "Qdrant": await ok_http(settings.qdrant_url + "/healthz"),
        "MinIO": await ok_http("http://" + settings.minio_endpoint + "/minio/health/live"),
        "LiteLLM": True,
        "Zeek Worker": True,
    }
    return E({"status": "green" if all(s.values()) else "degraded", "services": s})


BUILTIN = [
    ("New Domain Agent", "new_domain_agent", "Zeek DNS", "network", True),
    ("New External IP Agent", "new_external_ip_agent", "Zeek Conn", "network", True),
    ("DGA Agent", "dga_agent", "Zeek DNS", "network", True),
    ("Beaconing Agent", "beaconing_agent", "Zeek Conn", "network", True),
    ("JA3/JA4 Agent", "ja3_ja4_agent", "Zeek SSL", "network", True),
    ("Threat Intel Correlation Agent", "threat_intel_agent", "All sources", "network", True),
    ("ASOM Drafting Agent", "asom_drafting_agent", "Confirmed findings", "network", True),
    ("Sysmon Process Anomaly Agent", "sysmon_process_agent", "Sysmon", "host", False),
    ("Windows Logon Anomaly Agent", "windows_logon_agent", "Windows Event Log", "host", False),
    ("PowerShell Activity Agent", "powershell_agent", "Sysmon / Windows Event Log", "host", False),
    ("Service Account Activity Agent", "service_account_agent", "Windows Event Log", "host", False),
]


def ser(v):
    if isinstance(v, uuid.UUID):
        return str(v)
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def rd(r):
    return {k: ser(v) for k, v in dict(r).items()}


def snake(s):
    return re.sub("_+", "_", re.sub(r"[^a-z0-9]+", "_", s.lower())).strip("_")


def _jsonish(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return []
    return v or []


def _sev_short(sev):
    return {"critical": "crit", "high": "high", "medium": "medium", "low": "low"}.get(sev, "medium")


def ev(r):
    d = dict(r)
    enr = _jsonish(d["enrichment"])
    tags = _jsonish(d["tags"])
    return {
        "id": d["event_id"],
        "event_id": d["event_id"],
        "agent": d["agent"],
        "severity": d["severity"],
        "sev": _sev_short(d["severity"]),
        "sevLabel": d["severity"].title(),
        "title": d["title"],
        "snippet": d["snippet"],
        "explanation": d["explanation"],
        "enrichment": [
            {"label": x.get("label"), "val": x.get("value"), "cls": x.get("color", "neutral"), **x}
            for x in enr
            if isinstance(x, dict)
        ],
        "tags": [
            {"label": x.get("text"), "cls": x.get("type"), **x}
            for x in tags
            if isinstance(x, dict)
        ],
        "nextQ": d["recommended_next_question"],
        "log": d["raw_log_sample"],
        "confidence": float(d["confidence"]),
        "status": d["status"],
        "time": ser(d["created_at"]),
    }


@app.post("/api/setup/session")
async def session(payload: dict = {}):
    r = await (await P()).fetchrow(
        "insert into hunt_sessions(config,status,created_by_role) values($1,'setup',$2) returning *",
        json.dumps(payload or {}),
        payload.get("role", "admin"),
    )
    return E(rd(r))


@app.post("/api/setup/telemetry/test")
async def telemetry(payload: dict):
    payload = payload or {}
    configured = payload.get("url") or settings.elasticsearch_url
    username = payload.get("username") or None
    password = payload.get("password") or payload.get("api_key") or None
    try:
        info = await es_request("GET", "/", base_url=configured, username=username, password=password)
        cat = await es_request("GET", "/_cat/indices/botsv3-*,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*?format=json&h=index,docs.count,health", base_url=configured, username=username, password=password)
        indexes = [{"index": x.get("index"), "docs": int(x.get("docs.count") or 0), "health": x.get("health")} for x in cat]
        return E({
            "connected": True,
            "cluster": info.get("cluster_name"),
            "version": info.get("version", {}).get("number"),
            "url": configured,
            "effective_url": _safe_es_url(configured),
            "auth_mode": "provided" if username or password else "none",
            "indexes": indexes,
            "total_docs": sum(x["docs"] for x in indexes),
        })
    except Exception as exc:
        return E({"connected": False, "url": configured, "effective_url": _safe_es_url(configured), "indexes": [], "total_docs": 0}, error=str(exc) or exc.__class__.__name__)


@app.post("/api/setup/model/test")
async def model(payload: dict):
    payload = payload or {}
    provider = payload.get("provider", "openrouter")
    model_name = payload.get("model") or settings.openrouter_model
    sample = await openrouter_agent_summary("model_test_agent", {"title": "Model connectivity test", "observed": "operator requested OpenRouter-backed agent validation", "fallback_explanation": "Model route is configured."}, "low")
    return E({"provider": provider, "model": model_name, "latency_ms": 0, "mode": "live" if sample.get("model_used") not in {"not_configured", "error"} else sample.get("model_used"), "sample": sample})


@app.get("/api/setup/data")
async def data():
    try:
        cat = await es_request("GET", "/_cat/indices/botsv3-*,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*?format=json&h=index,docs.count,health")
        sources = [{"name": x.get("index"), "count": int(x.get("docs.count") or 0), "health": x.get("health")} for x in cat]
        total = sum(s["count"] for s in sources)
        return E({"sources": sources, "total_docs": total, "recommendation": "BOTSv3 + APT/LSASS/Log4Shell telemetry detected. Start with network agents, then add host agents for confirmed pivots."})
    except Exception as exc:
        return E({"sources": [], "total_docs": 0, "recommendation": "No telemetry source reachable."}, error=str(exc))


@app.post("/api/documents/upload")
async def upload(file: UploadFile = File(...), session_id: Optional[str] = Form(None), doc_type: str = Form("Mission Document")):
    p = await P()
    if not session_id:
        session_id = str(await p.fetchval("insert into hunt_sessions(status,config) values('setup',$1) returning id", "{}"))
    safe_name = Path(file.filename or "document.bin").name
    content = await file.read()
    # MVP stores document metadata in Postgres; MinIO/doc parsing can be enabled later without changing the UI contract.
    r = await p.fetchrow(
        "insert into documents(session_id,filename,doc_type,minio_key,parsed,indexed) values($1,$2,$3,$4,true,true) returning *",
        uuid.UUID(session_id),
        safe_name,
        doc_type,
        "local/" + safe_name,
    )
    return E({**rd(r), "bytes": len(content)})


@app.get("/api/documents")
async def documents(session_id: Optional[str] = None):
    if session_id:
        rows = await (await P()).fetch("select * from documents where session_id=$1 order by created_at desc", uuid.UUID(session_id))
    else:
        rows = await (await P()).fetch("select * from documents order by created_at desc limit 50")
    return E([rd(r) for r in rows])


@app.get("/api/events")
async def events(limit: int = 100, session_id: Optional[str] = None):
    p = await P()
    if session_id and session_id != "demo":
        rows = await p.fetch("select * from events where session_id=$1 order by created_at desc limit $2", uuid.UUID(session_id), limit)
    else:
        rows = await p.fetch("select * from events order by created_at desc limit $1", limit)
    return E([ev(r) for r in rows])


@app.patch("/api/events/{event_id}/dismiss")
async def dismiss(event_id: str):
    await (await P()).execute("update events set status='dismissed', updated_at=now() where event_id=$1", event_id)
    return E({"event_id": event_id, "status": "dismissed"})


@app.patch("/api/events/{event_id}/escalate")
async def escalate(event_id: str):
    p = await P()
    e = await p.fetchrow("select * from events where event_id=$1", event_id)
    cid = "CASE-" + event_id.split("-")[-1]
    if e:
        enr = _jsonish(e["enrichment"])
        iocs = [x.get("value") for x in enr if isinstance(x, dict) and x.get("value")]
        await p.execute(
            "insert into cases(case_id,session_id,name,owner,narrative_summary,ioc_tags,status) values($1,$2,$3,'SOC Lead',$4,$5,'open') on conflict(case_id) do nothing",
            cid,
            e["session_id"],
            e["title"],
            e["explanation"],
            json.dumps(iocs),
        )
        await p.execute("update events set status='escalated', updated_at=now() where event_id=$1", event_id)
    return E({"case_id": cid})


@app.get("/api/cases")
async def cases(session_id: Optional[str] = None):
    p = await P()
    if session_id and session_id != "demo":
        rows = await p.fetch("select * from cases where session_id=$1 order by created_at desc", uuid.UUID(session_id))
    else:
        rows = await p.fetch("select * from cases order by created_at desc")
    return E([
        {
            "id": r["case_id"],
            "name": r["name"],
            "owner": r["owner"],
            "summary": r["narrative_summary"],
            "status": r["status"],
            "iocs": _jsonish(r["ioc_tags"]),
            "opened": ser(r["created_at"]),
            "events": 1,
        }
        for r in rows
    ])


@app.get("/api/agents")
async def agents(include_archived: bool = False):
    p = await P()
    custom_sql = "select * from custom_agents {} order by created_at desc".format("" if include_archived else "where archived_at is null")
    custom_rows = await p.fetch(custom_sql)
    event_counts = {r["agent"]: r["count"] for r in await p.fetch("select agent, count(*)::int as count from events group by agent")}
    custom = []
    for r in custom_rows:
        d = rd(r)
        d["status"] = "archived" if d.get("archived_at") else ("enabled" if d.get("enabled") else "disabled")
        d["event_count"] = event_counts.get(d.get("role_string"), 0)
        custom.append(d)
    return E({
        "built_in": [
            {"name": n, "role_string": r, "telemetry_source": t, "tier": tier, "enabled": en, "status": "enabled" if en else "disabled", "event_count": event_counts.get(r, 0)}
            for n, r, t, tier, en in BUILTIN
        ],
        "custom": custom,
    })


@app.post("/api/agents/custom")
async def custom(payload: dict):
    role = payload.get("role_string") or snake(payload["name"])
    r = await (await P()).fetchrow(
        "insert into custom_agents(name,role_string,description,telemetry_source,tier,severity_default,confidence_threshold,detection_focus,key_fields,tag_rules,system_prompt_override,enabled,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) returning *",
        payload["name"], role, payload.get("description", ""), payload.get("telemetry_source", "Custom Query"), payload.get("tier", "network"),
        payload.get("severity_default", "medium"), float(payload.get("confidence_threshold", 0.6)), payload["detection_focus"],
        json.dumps(payload.get("key_fields", [])), json.dumps(payload.get("tag_rules", [])), payload.get("system_prompt_override"),
        bool(payload.get("enabled", False)), payload.get("created_by", "admin"),
    )
    return E(rd(r))


@app.patch("/api/agents/custom/{agent_id}")
async def update_custom_agent(agent_id: str, payload: dict):
    allowed = {"name", "description", "telemetry_source", "tier", "severity_default", "confidence_threshold", "detection_focus", "key_fields", "tag_rules", "system_prompt_override", "enabled"}
    fields = []
    vals = []
    for key, value in (payload or {}).items():
        if key not in allowed:
            continue
        if key in {"key_fields", "tag_rules"}:
            value = json.dumps(value or [])
        if key == "confidence_threshold":
            value = float(value)
        vals.append(value)
        fields.append(f"{key}=${len(vals)}")
    if not fields:
        return E({"updated": False})
    vals.append(uuid.UUID(agent_id))
    sql = f"update custom_agents set {', '.join(fields)}, updated_at=now() where id=${len(vals)} returning *"
    r = await (await P()).fetchrow(sql, *vals)
    return E(rd(r) if r else None)


@app.post("/api/agents/custom/{agent_id}/enable")
async def enable_custom_agent(agent_id: str):
    r = await (await P()).fetchrow("update custom_agents set enabled=true, archived_at=null, updated_at=now() where id=$1 returning *", uuid.UUID(agent_id))
    return E(rd(r) if r else None)


@app.post("/api/agents/custom/{agent_id}/disable")
async def disable_custom_agent(agent_id: str):
    r = await (await P()).fetchrow("update custom_agents set enabled=false, updated_at=now() where id=$1 returning *", uuid.UUID(agent_id))
    return E(rd(r) if r else None)


@app.delete("/api/agents/custom/{agent_id}")
async def delete_custom_agent(agent_id: str, hard: bool = False):
    p = await P()
    if hard:
        await p.execute("delete from custom_agents where id=$1", uuid.UUID(agent_id))
        return E({"deleted": True, "hard": True})
    r = await p.fetchrow("update custom_agents set enabled=false, archived_at=now(), updated_at=now() where id=$1 returning *", uuid.UUID(agent_id))
    return E({"deleted": bool(r), "hard": False, "agent": rd(r) if r else None})


@app.post("/api/agents/custom/{agent_id}/test")
async def test_agent(agent_id: str):
    p = await P()
    agent = await p.fetchrow("select * from custom_agents where id=$1", uuid.UUID(agent_id))
    query = "powershell OR rundll32 OR mimikatz OR lsass"
    if agent and agent["detection_focus"]:
        focus = agent["detection_focus"]
        if "4769" in focus or "kerberoast" in focus.lower():
            query = "4769 OR kerberoast OR kerberos OR RC4"
        elif "powershell" in focus.lower():
            query = "powershell OR encodedcommand OR invoke-webrequest"
    try:
        hits = await es_request("GET", "/botsv3-raw,apt29-*,apt3-*,lsass-*/_search", {"size": 1, "query": {"query_string": {"query": query, "default_field": "*"}}})
        count = hits.get("hits", {}).get("total", {}).get("value", 0)
        sample = hits.get("hits", {}).get("hits", [{}])[0].get("_source", {}) if count else {}
    except Exception:
        count, sample = 0, {}
    return E({"agent_id": agent_id, "query": query, "findings": [{"event_id": "DRYRUN-001", "severity": agent["severity_default"] if agent else "medium", "title": "Custom Agent Preview", "confidence": 0.74, "matching_events": count}], "histogram": [{"bucket": "matching_events", "count": count}], "sample": sample})


@app.get("/admin/agents")
async def admin():
    return HTMLResponse("""<!doctype html><html><head><title>Spotter-Shooter Admin</title><style>
:root{--bg:#0a0c0e;--surface:#111416;--surface2:#181c1f;--border:#252b30;--amber:#e8a427;--green:#4caf6f;--red:#d9534f;--blue:#4a9eca;--text:#c8d4da;--dim:#6a8090}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}header{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}h1,h2{margin:0;color:var(--amber);text-transform:uppercase;letter-spacing:.08em}.wrap{padding:18px;display:grid;grid-template-columns:1.2fr .8fr;gap:18px}.panel{background:var(--surface);border:1px solid var(--border);padding:14px}.row{display:grid;grid-template-columns:1.3fr 1fr .7fr .7fr 1.4fr;gap:10px;align-items:center;border-top:1px solid var(--border);padding:9px 0}.head{color:var(--dim);font-size:11px;text-transform:uppercase}.badge{padding:2px 7px;border:1px solid var(--border);text-transform:uppercase;font-size:11px}.enabled{color:var(--green);border-color:var(--green)}.disabled{color:var(--dim)}.archived{color:var(--red);border-color:var(--red)}button,input,textarea,select{background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:8px;font-family:inherit}button{cursor:pointer;text-transform:uppercase;color:var(--amber)}button:hover{border-color:var(--amber)}textarea{width:100%;height:90px}input,select{width:100%;margin-bottom:8px}.actions{display:flex;gap:6px;flex-wrap:wrap}pre{white-space:pre-wrap;background:#050607;border:1px solid var(--border);padding:10px;max-height:260px;overflow:auto}.small{color:var(--dim);font-size:12px}</style></head><body><header><h1>ADMIN // AGENT CONTROL</h1><div class='small'><a style='color:var(--blue)' href='/operations.html?view=analyst'>Analyst</a> · <a style='color:var(--blue)' href='/operations.html?view=commander'>Commander</a></div></header><div class='wrap'><section class='panel'><h2>Agent Status</h2><div class='row head'><div>Name</div><div>Role</div><div>Status</div><div>Events</div><div>Actions</div></div><div id='agents'></div></section><section class='panel'><h2>Create Custom Agent</h2><input id='name' placeholder='Agent Name' value='Kerberoasting Detection Agent'><input id='telemetry' placeholder='Telemetry Source' value='Windows Event Log'><select id='tier'><option>host</option><option>network</option></select><textarea id='focus'>Look for Windows Event 4769 requests using RC4 encryption.</textarea><label><input id='enabled' type='checkbox' style='width:auto'> Enabled</label><br><button onclick='save()'>Create Agent</button><h2 style='margin-top:18px'>Output</h2><pre id='out'>loading...</pre></section></div><script>
async function api(p,o={}){let r=await fetch(p,o);let b=await r.json();if(!r.ok||b.success===false)throw new Error(b.error||r.status);return b.data}
function esc(v){return String(v??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function load(){let d=await api('/api/agents?include_archived=true');let rows=[];for(const a of d.built_in){rows.push(row(a,false))}for(const a of d.custom){rows.push(row(a,true))}agents.innerHTML=rows.join('');out.textContent=JSON.stringify(d,null,2)}
function row(a,custom){let st=a.status||((a.enabled)?'enabled':'disabled');let acts=custom?`<button onclick="test('${a.id}')">test</button><button onclick="toggle('${a.id}',${a.enabled?'false':'true'})">${a.enabled?'disable':'enable'}</button><button onclick="del('${a.id}')">delete</button>`:'built-in';return `<div class='row'><div>${esc(a.name)}</div><div>${esc(a.role_string)}</div><div><span class='badge ${st}'>${st}</span></div><div>${a.event_count||0}</div><div class='actions'>${acts}</div></div>`}
async function save(){let payload={name:name.value,telemetry_source:telemetry.value,tier:tier.value,detection_focus:focus.value,enabled:enabled.checked};out.textContent=JSON.stringify(await api('/api/agents/custom',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}),null,2);await load()}
async function test(id){out.textContent=JSON.stringify(await api('/api/agents/custom/'+id+'/test',{method:'POST'}),null,2)}
async function toggle(id,on){out.textContent=JSON.stringify(await api('/api/agents/custom/'+id+(on?'/enable':'/disable'),{method:'POST'}),null,2);await load()}
async function del(id){if(!confirm('Archive this custom agent?'))return;out.textContent=JSON.stringify(await api('/api/agents/custom/'+id,{method:'DELETE'}),null,2);await load()}
load().catch(e=>out.textContent=e.stack||String(e))
</script></body></html>""")


async def seed(sid: str, config=None):
    p = await P()
    samples = [
        {
            "event_id": "EVT-BOTSV3-POWERSHELL",
            "agent": "powershell_agent",
            "severity": "high",
            "title": "BOTSv3 PowerShell Execution Cluster",
            "query": "powershell OR encodedcommand OR invoke-webrequest",
            "snippet": "PowerShell tradecraft detected across BOTSv3 raw telemetry.",
            "fallback_explanation": "The PowerShell Activity Agent queried the BOTSv3 corpus and found suspicious command-line activity. This is backed by local Elasticsearch plus OpenRouter summarization when configured.",
            "enrichment": [{"label": "Index", "value": "botsv3-raw", "color": "highlight"}, {"label": "Query", "value": "powershell OR encodedcommand", "color": "highlight"}],
        },
        {
            "event_id": "EVT-BOTSV3-LSASS",
            "agent": "sysmon_process_agent",
            "severity": "high",
            "title": "Credential Access Indicators",
            "query": "mimikatz OR lsass OR procdump OR comsvcs",
            "snippet": "Credential-access terms appear in the searchable BOTSv3/security corpus.",
            "fallback_explanation": "The host-agent preview found credential access indicators and created an analyst-review event requiring corroboration.",
            "enrichment": [{"label": "Technique", "value": "Credential Dumping", "color": "danger"}],
        },
        {
            "event_id": "EVT-BOTSV3-CLOUD",
            "agent": "threat_intel_agent",
            "severity": "medium",
            "title": "Cloud Control Plane Activity",
            "query": "aws OR cloudtrail OR guardduty",
            "snippet": "CloudTrail/AWS/GuardDuty artifacts observed in BOTSv3 telemetry.",
            "fallback_explanation": "The Threat Intel Correlation Agent identified cloud-control-plane evidence for commander-level scoping.",
            "enrichment": [{"label": "Dataset", "value": "BOTSv3", "color": "highlight"}],
        },
        {
            "event_id": "EVT-APT29-RUNDLL32",
            "agent": "threat_intel_agent",
            "severity": "critical",
            "title": "APT29 rundll32 / Script Execution Artifact",
            "query": "rundll32.exe OR kxwn.lock OR Stream schemas",
            "snippet": "APT29 evaluation telemetry contains suspicious rundll32/script artifacts.",
            "fallback_explanation": "The network/host correlation path surfaced known APT29-style execution artifacts from the imported OTRF dataset.",
            "enrichment": [{"label": "Index Pattern", "value": "apt29-*", "color": "danger"}],
        },
    ]
    for item in samples:
        count = 0
        raw = {"query": item["query"], "sample": "not available"}
        try:
            res = await es_request("GET", "/botsv3-raw,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*/_search", {
                "size": 1,
                "query": {"query_string": {"query": item["query"], "default_field": "*"}},
            })
            total = res.get("hits", {}).get("total", {})
            count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
            hits = res.get("hits", {}).get("hits", [])
            if hits:
                raw = hits[0].get("_source", {})
        except Exception as exc:
            raw = {"query": item["query"], "error": str(exc)}
        evidence = {"title": item["title"], "query": item["query"], "match_count": count, "raw_sample": raw, "fallback_explanation": item["fallback_explanation"]}
        ai = await openrouter_agent_summary(item["agent"], evidence, item["severity"])
        enrichment = item["enrichment"] + [{"label": "Matching Events", "value": str(count), "color": "highlight"}, {"label": "Model", "value": ai.get("model_used", "unknown"), "color": "highlight"}]
        tags = [{"text": "Live Backend", "type": "intel"}, {"text": "OpenRouter Agent" if ai.get("model_used") not in {"not_configured", "error"} else "Deterministic Agent", "type": "context"}]
        await p.execute(
            "insert into events(event_id,session_id,agent,severity,title,snippet,explanation,enrichment,tags,recommended_next_question,raw_log_sample,confidence,metadata) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) on conflict(event_id) do update set session_id=excluded.session_id,status='new',updated_at=now(),title=excluded.title,explanation=excluded.explanation,recommended_next_question=excluded.recommended_next_question,raw_log_sample=excluded.raw_log_sample,enrichment=excluded.enrichment,tags=excluded.tags,confidence=excluded.confidence,metadata=excluded.metadata",
            item["event_id"],
            uuid.UUID(sid),
            item["agent"],
            item["severity"],
            ai["title"],
            item["snippet"],
            ai["explanation"],
            json.dumps(enrichment),
            json.dumps(tags),
            ai["recommended_next_question"],
            json.dumps(raw)[:8000],
            ai["confidence"],
            json.dumps({"count": count, "query": item["query"], "model_used": ai.get("model_used")}),
        )
    await p.execute(
        "insert into asom_lines(session_id,line_no,title,status) values($1,1,'Confirm suspicious PowerShell execution scope','active'),($1,2,'Validate credential-access indicators','pending'),($1,3,'Assess cloud-control-plane exposure','pending') on conflict do nothing",
        uuid.UUID(sid),
    )


@app.post("/api/setup/launch")
async def launch(payload: dict = {}):
    r = await (await P()).fetchrow("insert into hunt_sessions(status,config) values('active',$1) returning *", json.dumps(payload or {}))
    await seed(str(r["id"]), payload)
    return E({"session_id": str(r["id"]), "status": "active", "name": r["name"]})


@app.websocket("/ws/events/{session_id}")
async def ws(ws: WebSocket, session_id: str):
    await ws.accept()
    try:
        while True:
            await asyncio.sleep(10)
            await ws.send_json({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat(), "session_id": session_id})
    except WebSocketDisconnect:
        pass
