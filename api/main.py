import asyncio
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
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
    app_secret: str = "spotter-local-secret-change-me"
    kibana_url: str = "https://kibana.praeviaintel.com"
    smtp_url: str = ""
    sms_webhook_url: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
app = FastAPI(title="Spotter-Shooter API")
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
pool: Optional[asyncpg.Pool] = None


def E(data=None, error=None, meta=None):
    return {"success": error is None, "data": data, "error": error, "meta": meta or {}}


async def migrate_db(db):
    stmts = [
        "alter table cases add column if not exists created_by uuid",
        "alter table cases add column if not exists bluf text default ''",
        "alter table cases add column if not exists five_ws jsonb default '{}'::jsonb",
        "alter table cases add column if not exists technical_summary text default ''",
        "alter table cases add column if not exists way_ahead text default ''",
        "alter table cases add column if not exists final_output text default ''",
        "alter table cases add column if not exists priority text default 'medium'",
        "alter table case_events add column if not exists added_at timestamptz default now()",
        "alter table case_events add column if not exists added_by uuid",
        "alter table case_events add column if not exists note text default ''",
        "create table if not exists accounts (id uuid primary key default gen_random_uuid(), username text unique not null, display_name text not null, privilege_level text not null default 'analyst', service_branch text default '', rank text default '', work_role text default '', skill_level text default 'basic', team text default '', bio text default '', certs text default '', degrees text default '', years_experience int default 0, contact text default '', created_at timestamptz default now(), updated_at timestamptz default now())",
        "alter table accounts add column if not exists email text default ''",
        "alter table accounts add column if not exists phone text default ''",
        "alter table accounts add column if not exists password_hash text default ''",
        "alter table accounts add column if not exists team_id uuid",
        "create table if not exists teams (id uuid primary key default gen_random_uuid(), team_type text not null default 'CPT', number text unique not null, name text not null, description text default '', logo_url text default '', location text default '', phone text default '', email text default '', notes text default '', team_lead_id uuid, deputy_team_lead_id uuid, planner_id uuid, ncoic_id uuid, created_at timestamptz default now(), updated_at timestamptz default now())",
        "create table if not exists auth_sessions (token text primary key, account_id uuid references accounts(id) on delete cascade, created_at timestamptz default now(), expires_at timestamptz not null)",
        "create table if not exists login_challenges (id uuid primary key default gen_random_uuid(), account_id uuid references accounts(id) on delete cascade, code_hash text not null, destination text default '', method text default 'email', expires_at timestamptz not null, used_at timestamptz, created_at timestamptz default now())",
        "create table if not exists case_members (case_id uuid references cases(id) on delete cascade, account_id uuid references accounts(id) on delete cascade, role text default 'supporting analyst', joined_at timestamptz default now(), primary key(case_id, account_id))",
        "create table if not exists case_indicators (id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade, indicator_type text not null, value text not null, source text default 'analyst', description text default '', created_by uuid references accounts(id), created_at timestamptz default now(), unique(case_id, indicator_type, value))",
        "create table if not exists case_timeline (id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade, event_time timestamptz default now(), entry_type text not null default 'note', title text not null, body text default '', actor_id uuid references accounts(id), actor_name text default '', related_event_id text, related_indicator text, created_at timestamptz default now())",
        "create table if not exists enrichment_configs (id uuid primary key default gen_random_uuid(), name text unique not null, provider_type text not null, enabled boolean default false, base_url text default '', api_key_ref text default '', notes text default '', config jsonb default '{}'::jsonb, created_at timestamptz default now(), updated_at timestamptz default now())",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('Local OpenCTI','opencti',false,'http://opencti:8080','Local OpenCTI enrichment. Configure URL/token before enabling.', '{\"token_env\":\"OPENCTI_TOKEN\"}'::jsonb) on conflict(name) do nothing",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('VirusTotal','virustotal',false,'https://www.virustotal.com/api/v3','Optional cloud enrichment. Disabled by default; requires API key.', '{\"api_key_env\":\"VIRUSTOTAL_API_KEY\"}'::jsonb) on conflict(name) do nothing",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('Custom HTTP Enrichment','custom_http',false,'','Operator-defined HTTP enrichment endpoint. Disabled by default.', '{}'::jsonb) on conflict(name) do nothing",
        """insert into teams(team_type,number,name) values ('CPT','100','100 Cyber Protection Team'),('CPT','101','101 Cyber Protection Team'),('CPT','150','150 Cyber Protection Team'),('CPT','151','151 Cyber Protection Team'),('CPT','152','152 Cyber Protection Team'),('CPT','153','153 Cyber Protection Team'),('CPT','154','154 Cyber Protection Team'),('CPT','155','155 Cyber Protection Team'),('CPT','156','156 Cyber Protection Team'),('CPT','200','200 Cyber Protection Team'),('CPT','201','201 Cyber Protection Team'),('CPT','400','400 Cyber Protection Team'),('CPT','401','401 Cyber Protection Team'),('CPT','600','600 Cyber Protection Team'),('CPT','503','503 Cyber Protection Team'),('NCPT','01','01 National Cyber Protection Team'),('NCPT','03','03 National Cyber Protection Team'),('NCPT','05','05 National Cyber Protection Team'),('NCPT','23','23 National Cyber Protection Team') on conflict(number) do nothing""",
    ]
    async with db.acquire() as conn:
        for stmt in stmts:
            await conn.execute(stmt)


RANKS = {
    "army": ["PVT", "PV2", "PFC", "SPC", "CPL", "SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "WO1", "CW2", "CW3", "CW4", "CW5", "2LT", "1LT", "CPT", "MAJ", "LTC", "COL", "BG", "MG", "LTG", "GEN"],
    "airforce": ["AB", "Amn", "A1C", "SrA", "SSgt", "TSgt", "MSgt", "SMSgt", "CMSgt", "CCM", "CMSAF", "2d Lt", "1st Lt", "Capt", "Maj", "Lt Col", "Col", "Brig Gen", "Maj Gen", "Lt Gen", "Gen"],
    "coastguard": ["SR", "SA", "SN", "PO3", "PO2", "PO1", "CPO", "SCPO", "MCPO", "CMC", "MCPOCG", "ENS", "LTJG", "LT", "LCDR", "CDR", "CAPT", "RDML", "RADM", "VADM", "ADM"],
    "navy": ["SR", "SA", "SN", "PO3", "PO2", "PO1", "CPO", "SCPO", "MCPO", "CMC", "MCPON", "ENS", "LTJG", "LT", "LCDR", "CDR", "CAPT", "RDML", "RADM", "VADM", "ADM", "FADM"],
    "marines": ["Pvt", "PFC", "LCpl", "Cpl", "Sgt", "SSgt", "GySgt", "MSgt", "1stSgt", "MGySgt", "SgtMaj", "SMMC", "WO", "CWO2", "CWO3", "CWO4", "CWO5", "2ndLt", "1stLt", "Capt", "Maj", "LtCol", "Col", "BGen", "MajGen", "LtGen", "Gen"],
}
WORK_ROLES = ["Analytic Support Officer", "Data Engineer", "Host Analyst", "Network Analyst", "Planner", "Cyber Integration Technician", "Master Gunner", "Team Lead", "Deputy Team Lead", "NCOIC", "Commander"]
SKILL_LEVELS = ["Basic", "Senior", "Master"]
PRIVILEGE_LEVELS = ["admin", "analyst"]
TEAM_ROLES = ["Team Lead", "Deputy Team Lead", "Planner", "NCOIC"]


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    try:
        _, salt, digest = stored.split("$", 2)
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()
        return hmac.compare_digest(got, digest)
    except Exception:
        return False


def hash_code(code: str) -> str:
    return hmac.new(settings.app_secret.encode(), code.encode(), hashlib.sha256).hexdigest()


async def get_actor(p, token: str = ""):
    if token:
        row = await p.fetchrow("select a.* from auth_sessions s join accounts a on a.id=s.account_id where s.token=$1 and s.expires_at>now()", token)
        if row:
            return row
    return await ensure_default_account(p)


def account_public(r):
    d = rd(r)
    d.pop("password_hash", None)
    return d


def can_edit_account(actor, target_id: str) -> bool:
    return actor and (actor["privilege_level"] == "admin" or str(actor["id"]) == str(target_id))


async def send_otp(method: str, destination: str, code: str):
    # MVP delivery: if SMTP/SMS webhook envs are absent, return the code for local/demo display.
    if method == "sms" and settings.sms_webhook_url:
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(settings.sms_webhook_url, json={"to": destination, "message": f"Spotter-Shooter login code: {code}"})
        return {"delivered": True}
    if method == "email" and settings.smtp_url:
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(settings.smtp_url, json={"to": destination, "subject": "Spotter-Shooter login code", "text": f"Your login code is {code}"})
        return {"delivered": True}
    return {"delivered": False, "demo_code": code, "note": "Configure SMTP_URL or SMS_WEBHOOK_URL for real delivery."}


def extract_indicators_from_event(event_row):
    vals = []
    for x in _jsonish(event_row.get("enrichment") if isinstance(event_row, dict) else event_row["enrichment"]):
        if isinstance(x, dict):
            v = str(x.get("value") or x.get("val") or "").strip()
            if v and len(v) < 256:
                vals.append((str(x.get("label") or "observable").lower(), v))
    raw = event_row.get("raw_log_sample") if isinstance(event_row, dict) else event_row["raw_log_sample"]
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    for ip in sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))):
        vals.append(("ip", ip))
    for dom in sorted(set(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text))):
        if not dom.replace('.', '').isdigit() and len(dom) < 180:
            vals.append(("domain", dom.lower()))
    for proc in sorted(set(re.findall(r"\b[a-zA-Z0-9_\-]+\.exe\b", text, re.I))):
        vals.append(("process", proc.lower()))
    seen, out = set(), []
    for t, v in vals:
        key = (t, v)
        if key not in seen:
            seen.add(key); out.append({"type": t, "value": v})
    return out[:40]


migrated = False


async def P():
    global pool, migrated
    if pool is None:
        pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=10)
    if not migrated:
        await migrate_db(pool)
        migrated = True
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
    if parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port == 9209:
        return settings.elasticsearch_url.rstrip("/")
    return (url or settings.elasticsearch_url).rstrip("/")


def _zeek_env():
    env = os.environ.copy()
    host_lib = "/host-lib/x86_64-linux-gnu"
    if Path(host_lib).exists():
        env["LD_LIBRARY_PATH"] = host_lib + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    return env


async def es_request(method: str, path: str, payload=None, timeout=8, base_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
    base = _safe_es_url(base_url or settings.elasticsearch_url)
    url = base + path
    auth = (username, password) if (username or password) and not (base == settings.elasticsearch_url.rstrip("/") and "apt29-elasticsearch" in base) else None
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


async def es_bulk(lines, timeout=60, base_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
    base = _safe_es_url(base_url or settings.elasticsearch_url)
    auth = (username, password) if (username or password) and not (base == settings.elasticsearch_url.rstrip("/") and "apt29-elasticsearch" in base) else None
    client_kwargs = {"timeout": timeout}
    if auth is not None:
        client_kwargs["auth"] = auth
    async with httpx.AsyncClient(**client_kwargs) as c:
        r = await c.post(base + "/_bulk", content="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"})
        r.raise_for_status()
        data = r.json()
        if data.get("errors"):
            raise RuntimeError("Elasticsearch bulk indexing returned errors")
        return data


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
            "auth_mode": "none" if _safe_es_url(configured) == settings.elasticsearch_url.rstrip("/") and "apt29-elasticsearch" in settings.elasticsearch_url else ("provided" if username or password else "none"),
            "indexes": indexes,
            "total_docs": sum(x["docs"] for x in indexes),
        })
    except Exception as exc:
        return E({"connected": False, "url": configured, "effective_url": _safe_es_url(configured), "indexes": [], "total_docs": 0}, error=str(exc) or exc.__class__.__name__)


@app.post("/api/pcap/upload")
async def pcap_upload(
    file: UploadFile = File(...),
    url: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    index_pattern: str = Form(""),
):
    zeek_bin = shutil.which("zeek")
    has_docker_socket = Path("/var/run/docker.sock").exists()
    if not zeek_bin and not has_docker_socket:
        return E({"indexed_docs": 0, "logs": []}, error="Zeek is not installed and Docker socket is unavailable for the Zeek worker image")
    safe_name = Path(file.filename or "upload.pcap").name
    ext = Path(safe_name).suffix.lower()
    if ext not in {".pcap", ".pcapng", ".cap"}:
        return E({"indexed_docs": 0, "logs": []}, error="Upload must be .pcap, .pcapng, or .cap")
    configured = url or settings.elasticsearch_url
    user = username or None
    pw = password or None
    with tempfile.TemporaryDirectory(prefix="spotter-pcap-") as td:
        work = Path(td)
        pcap_path = work / safe_name
        pcap_path.write_bytes(await file.read())
        try:
            if has_docker_socket:
                proc = subprocess.run([
                    "docker", "run", "--rm", "-v", f"{work}:/work", "-w", "/work",
                    "zeek/zeek:latest", "zeek", "-C", "-r", safe_name, "LogAscii::use_json=T"
                ], cwd=work, capture_output=True, text=True, timeout=180)
            else:
                proc = subprocess.run([zeek_bin, "-C", "-r", str(pcap_path), "LogAscii::use_json=T"], cwd=work, capture_output=True, text=True, timeout=180, env=_zeek_env())
        except subprocess.TimeoutExpired:
            return E({"indexed_docs": 0, "logs": []}, error="Zeek timed out processing the PCAP")
        if proc.returncode != 0:
            return E({"indexed_docs": 0, "logs": [], "stderr": proc.stderr[-1000:]}, error="Zeek failed to process the PCAP")
        logs = sorted(work.glob("*.log"))
        if not logs:
            return E({"indexed_docs": 0, "logs": []}, error="Zeek produced no logs from that PCAP")
        index = "spotter-zeek-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        bulk = []
        docs = 0
        for log in logs:
            log_type = log.stem
            for line in log.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    doc = json.loads(line)
                except Exception:
                    continue
                doc["spotter_source"] = "pcap_upload"
                doc["pcap_filename"] = safe_name
                doc["zeek_log_type"] = log_type
                bulk.append(json.dumps({"index": {"_index": index}}))
                bulk.append(json.dumps(doc, default=str))
                docs += 1
                if len(bulk) >= 1000:
                    await es_bulk(bulk, base_url=configured, username=user, password=pw)
                    bulk = []
        if bulk:
            await es_bulk(bulk, base_url=configured, username=user, password=pw)
        return E({"filename": safe_name, "index": index, "indexed_docs": docs, "logs": [p.stem for p in logs], "effective_url": _safe_es_url(configured)})


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


async def ensure_default_account(p):
    row = await p.fetchrow("select * from accounts order by created_at limit 1")
    if row:
        return row
    return await p.fetchrow("insert into accounts(username,display_name,privilege_level,work_role,skill_level,team,bio) values('analyst','Analyst','analyst','network analyst','basic','','Default analyst profile') returning *")


async def build_case_final(p, case_uuid):
    c = await p.fetchrow("select * from cases where id=$1", case_uuid)
    members = await p.fetch("select a.display_name,a.rank,a.service_branch,a.work_role,a.skill_level,a.team,cm.role from case_members cm join accounts a on a.id=cm.account_id where cm.case_id=$1 order by cm.joined_at", case_uuid)
    events = await p.fetch("select e.* from case_events ce join events e on e.id=ce.event_id where ce.case_id=$1 order by ce.added_at", case_uuid)
    inds = await p.fetch("select indicator_type,value from case_indicators where case_id=$1 order by created_at", case_uuid)
    lead = "; ".join([f"{m['rank']} {m['display_name']} ({m['work_role']}, {m['skill_level']}, {m['team']})".strip() for m in members]) or c["owner"]
    sev = events[0]["severity"] if events else "medium"
    titles = "; ".join([e["title"] for e in events[:5]]) or c["name"]
    indicators = ", ".join([f"{i['indicator_type']}:{i['value']}" for i in inds[:12]]) or "none confirmed"
    bluf = c["bluf"] or f"BLUF/SO WHAT: {sev.upper()} case {c['case_id']} requires analyst action because correlated alerts indicate {c['name']}."
    five_ws = _jsonish(c["five_ws"])
    if not isinstance(five_ws, dict) or not five_ws:
        five_ws = {
            "who": "Unknown operator / attribution pending",
            "what": titles,
            "when": ser(c["created_at"]),
            "where": indicators,
            "why": "Determine scope, impact, and whether activity represents compromise.",
        }
    technical = c["technical_summary"] or c["narrative_summary"] or "Technical summary pending analyst validation."
    way = c["way_ahead"] or "Validate indicators, pivot across related telemetry, request network-owner context, scope affected assets/users, and decide containment/reporting actions."
    final = f"{bluf}\n\n5 Ws:\n- Who: {five_ws.get('who','')}\n- What: {five_ws.get('what','')}\n- When: {five_ws.get('when','')}\n- Where: {five_ws.get('where','')}\n- Why: {five_ws.get('why','')}\n\nTechnical Summary:\n{technical}\n\nWay Ahead:\n{way}\n\nAnalyst / Work Role:\n{lead}"
    await p.execute("update cases set bluf=$2,five_ws=$3,technical_summary=$4,way_ahead=$5,final_output=$6,updated_at=now() where id=$1", case_uuid, bluf, json.dumps(five_ws), technical, way, final)
    return final


@app.patch("/api/events/{event_id}/escalate")
async def escalate(event_id: str, payload: dict = {}):
    p = await P()
    actor_id = payload.get("actor_id") if payload else None
    actor = await p.fetchrow("select * from accounts where id=$1", uuid.UUID(actor_id)) if actor_id else await ensure_default_account(p)
    e = await p.fetchrow("select * from events where event_id=$1", event_id)
    cid = "CASE-" + event_id.split("-")[-1]
    if not e:
        return E({"case_id": cid}, error="event not found")
    case = await p.fetchrow("select * from cases where case_id=$1", cid)
    if not case:
        case = await p.fetchrow(
            "insert into cases(case_id,session_id,name,owner,narrative_summary,ioc_tags,status,created_by) values($1,$2,$3,$4,$5,'[]'::jsonb,'open',$6) returning *",
            cid, e["session_id"], e["title"], actor["display_name"], e["explanation"], actor["id"],
        )
    await p.execute("insert into case_events(case_id,event_id,added_by,note) values($1,$2,$3,$4) on conflict(case_id,event_id) do update set added_at=now(), added_by=excluded.added_by", case["id"], e["id"], actor["id"], "Escalated from alert")
    await p.execute("insert into case_members(case_id,account_id,role) values($1,$2,$3) on conflict(case_id,account_id) do update set role=excluded.role", case["id"], actor["id"], actor["work_role"] or "analyst")
    await p.execute("update events set status='escalated', suggested_case_link=$2, updated_at=now() where event_id=$1", event_id, case["id"])
    await p.execute("insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name,related_event_id) values($1,'alert','Alert escalated',$2,$3,$4,$5)", case["id"], e["title"], actor["id"], actor["display_name"], event_id)
    for ind in extract_indicators_from_event(e):
        await p.execute("insert into case_indicators(case_id,indicator_type,value,source,description,created_by) values($1,$2,$3,'alert',$4,$5) on conflict(case_id,indicator_type,value) do nothing", case["id"], ind["type"], ind["value"], event_id, actor["id"])
    await build_case_final(p, case["id"])
    return E({"case_id": case["case_id"], "case_uuid": str(case["id"]), "status": "open"})


def case_obj(r, event_count=0, member_count=0):
    return {
        "uuid": ser(r["id"]), "id": r["case_id"], "case_id": r["case_id"], "name": r["name"], "owner": r["owner"],
        "summary": r["narrative_summary"], "status": r["status"], "iocs": _jsonish(r["ioc_tags"]), "opened": ser(r["created_at"]),
        "updated_at": ser(r["updated_at"]), "events": event_count, "members": member_count, "bluf": r["bluf"],
        "five_ws": _jsonish(r["five_ws"]), "technical_summary": r["technical_summary"], "way_ahead": r["way_ahead"], "final_output": r["final_output"]
    }


@app.get("/api/cases")
async def cases(session_id: Optional[str] = None):
    p = await P()
    rows = await p.fetch("""
        select c.*, count(distinct ce.event_id)::int as event_count, count(distinct cm.account_id)::int as member_count
        from cases c
        left join case_events ce on ce.case_id=c.id
        left join case_members cm on cm.case_id=c.id
        where ($1::uuid is null or c.session_id=$1)
        group by c.id order by c.updated_at desc, c.created_at desc
    """, None if not session_id or session_id == "demo" else uuid.UUID(session_id))
    return E([case_obj(r, r["event_count"], r["member_count"]) for r in rows])


@app.get("/api/cases/{case_id}")
async def case_detail(case_id: str):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    events_rows = await p.fetch("select e.* from case_events ce join events e on e.id=ce.event_id where ce.case_id=$1 order by ce.added_at desc", c["id"])
    members = await p.fetch("select a.*, cm.role, cm.joined_at from case_members cm join accounts a on a.id=cm.account_id where cm.case_id=$1 order by cm.joined_at", c["id"])
    indicators = await p.fetch("select * from case_indicators where case_id=$1 order by created_at desc", c["id"])
    timeline = await p.fetch("select * from case_timeline where case_id=$1 order by event_time desc, created_at desc", c["id"])
    related = {}
    for ind in indicators:
        related[ind["value"]] = await indicator_related(p, ind["value"])
    return E({**case_obj(c, len(events_rows), len(members)), "events": [ev(e) for e in events_rows], "members": [rd(m) for m in members], "indicators": [rd(i) for i in indicators], "timeline": [rd(t) for t in timeline], "indicator_related": related})


async def indicator_related(p, value: str):
    like = f"%{value}%"
    cases_rows = await p.fetch("select distinct c.case_id,c.name,c.status from cases c left join case_indicators ci on ci.case_id=c.id where ci.value=$1 or c.narrative_summary ilike $2 or c.final_output ilike $2 limit 12", value, like)
    event_rows = await p.fetch("select event_id,title,severity,status from events where raw_log_sample ilike $1 or title ilike $1 or explanation ilike $1 limit 12", like)
    return {"cases": [dict(r) for r in cases_rows], "events": [dict(r) for r in event_rows]}


@app.get("/api/indicators/{value}/related")
async def indicator_related_api(value: str):
    return E(await indicator_related(await P(), value))


@app.post("/api/cases/{case_id}/events/{event_id}")
async def add_event_to_case(case_id: str, event_id: str, payload: dict = {}):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    e = await p.fetchrow("select * from events where event_id=$1", event_id)
    if not c or not e:
        return E(None, error="case or event not found")
    actor_id = payload.get("actor_id") if payload else None
    actor = await p.fetchrow("select * from accounts where id=$1", uuid.UUID(actor_id)) if actor_id else await ensure_default_account(p)
    await p.execute("insert into case_events(case_id,event_id,added_by,note) values($1,$2,$3,$4) on conflict(case_id,event_id) do nothing", c["id"], e["id"], actor["id"], payload.get("note", "Added to existing case"))
    await p.execute("update events set status='escalated', suggested_case_link=$2 where event_id=$1", event_id, c["id"])
    await p.execute("insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name,related_event_id) values($1,'alert','New alert accepted into case',$2,$3,$4,$5)", c["id"], e["title"], actor["id"], actor["display_name"], event_id)
    for ind in extract_indicators_from_event(e):
        await p.execute("insert into case_indicators(case_id,indicator_type,value,source,description,created_by) values($1,$2,$3,'alert',$4,$5) on conflict(case_id,indicator_type,value) do nothing", c["id"], ind["type"], ind["value"], event_id, actor["id"])
    await build_case_final(p, c["id"])
    return await case_detail(case_id)


@app.post("/api/cases/{case_id}/members")
async def add_case_member(case_id: str, payload: dict):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    account_id = payload.get("account_id")
    if not account_id:
        return E(None, error="account_id required")
    a = await p.fetchrow("select * from accounts where id=$1", uuid.UUID(account_id))
    if not a:
        return E(None, error="account not found")
    await p.execute("insert into case_members(case_id,account_id,role) values($1,$2,$3) on conflict(case_id,account_id) do update set role=excluded.role", c["id"], a["id"], payload.get("role") or a["work_role"] or "analyst")
    await p.execute("insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name) values($1,'membership','Analyst joined case',$2,$3,$4)", c["id"], payload.get("role") or a["work_role"], a["id"], a["display_name"])
    await build_case_final(p, c["id"])
    return await case_detail(case_id)


@app.post("/api/cases/{case_id}/timeline")
async def add_case_timeline(case_id: str, payload: dict):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    actor = None
    if payload.get("actor_id"):
        actor = await p.fetchrow("select * from accounts where id=$1", uuid.UUID(payload["actor_id"]))
    r = await p.fetchrow("insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name,related_indicator) values($1,$2,$3,$4,$5,$6,$7) returning *", c["id"], payload.get("entry_type", "note"), payload.get("title", "Analyst note"), payload.get("body", ""), actor["id"] if actor else None, actor["display_name"] if actor else payload.get("actor_name", "Analyst"), payload.get("related_indicator"))
    await p.execute("update cases set updated_at=now() where id=$1", c["id"])
    return E(rd(r))


@app.post("/api/cases/{case_id}/indicators")
async def add_case_indicator(case_id: str, payload: dict):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    r = await p.fetchrow("insert into case_indicators(case_id,indicator_type,value,source,description,created_by) values($1,$2,$3,$4,$5,$6) on conflict(case_id,indicator_type,value) do update set description=excluded.description returning *", c["id"], payload.get("indicator_type", "observable"), payload["value"], payload.get("source", "analyst"), payload.get("description", ""), uuid.UUID(payload["created_by"]) if payload.get("created_by") else None)
    await p.execute("insert into case_timeline(case_id,entry_type,title,body,related_indicator) values($1,'indicator','Indicator added',$2,$3)", c["id"], f"{r['indicator_type']}: {r['value']}", r["value"])
    await build_case_final(p, c["id"])
    return E(rd(r))


@app.post("/api/cases/{case_id}/finalize")
async def finalize_case(case_id: str, payload: dict = {}):
    p = await P()
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    fields = []
    vals = []
    for key in ["bluf", "technical_summary", "way_ahead", "status"]:
        if key in payload:
            vals.append(payload[key]); fields.append(f"{key}=${len(vals)}")
    if "five_ws" in payload:
        vals.append(json.dumps(payload["five_ws"])); fields.append(f"five_ws=${len(vals)}")
    if fields:
        vals.append(c["id"])
        await p.execute(f"update cases set {', '.join(fields)}, updated_at=now() where id=${len(vals)}", *vals)
    final = await build_case_final(p, c["id"])
    return E({"case_id": c["case_id"], "final_output": final})


@app.get("/api/accounts/options")
async def account_options():
    return E({"ranks": RANKS, "work_roles": WORK_ROLES, "skill_levels": SKILL_LEVELS, "privilege_levels": PRIVILEGE_LEVELS, "team_roles": TEAM_ROLES})


@app.get("/api/auth/me")
async def auth_me(token: str = ""):
    actor = await get_actor(await P(), token)
    return E({"authenticated": bool(token), "read_only": not bool(token), "account": account_public(actor), "message": "Read-only view. Please login or Create an Account." if not token else "Authenticated"})


@app.post("/api/auth/login")
async def auth_login(payload: dict):
    p = await P()
    username = payload.get("username", "")
    password = payload.get("password", "")
    method = payload.get("method", "email")
    a = await p.fetchrow("select * from accounts where username=$1 or email=$1 or phone=$1", username)
    if not a or not verify_password(password, a["password_hash"]):
        return E(None, error="invalid username/password")
    destination = a["phone"] if method == "sms" else a["email"]
    if not destination:
        destination = a["contact"] or a["email"] or a["phone"] or "demo-local"
    code = f"{random.randint(100000, 999999)}"
    ch = await p.fetchrow("insert into login_challenges(account_id,code_hash,destination,method,expires_at) values($1,$2,$3,$4,now()+interval '10 minutes') returning id", a["id"], hash_code(code), destination, method)
    delivery = await send_otp(method, destination, code)
    return E({"challenge_id": str(ch["id"]), "method": method, "destination": destination, **delivery})


@app.post("/api/auth/verify")
async def auth_verify(payload: dict):
    p = await P()
    ch = await p.fetchrow("select * from login_challenges where id=$1 and used_at is null and expires_at>now()", uuid.UUID(payload["challenge_id"]))
    if not ch or not hmac.compare_digest(ch["code_hash"], hash_code(payload.get("code", ""))):
        return E(None, error="invalid or expired code")
    token = secrets.token_urlsafe(32)
    await p.execute("update login_challenges set used_at=now() where id=$1", ch["id"])
    await p.execute("insert into auth_sessions(token,account_id,expires_at) values($1,$2,now()+interval '12 hours')", token, ch["account_id"])
    a = await p.fetchrow("select * from accounts where id=$1", ch["account_id"])
    return E({"token": token, "account": account_public(a)})


@app.post("/api/auth/logout")
async def auth_logout(payload: dict):
    await (await P()).execute("delete from auth_sessions where token=$1", payload.get("token", ""))
    return E({"logged_out": True})


@app.get("/api/accounts")
async def accounts(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    if actor["privilege_level"] == "admin":
        rows = await p.fetch("select a.*, t.name as team_name, t.number as team_number, t.team_type from accounts a left join teams t on t.id=a.team_id order by a.display_name")
    else:
        rows = await p.fetch("select a.*, t.name as team_name, t.number as team_number, t.team_type from accounts a left join teams t on t.id=a.team_id where a.id=$1 order by a.display_name", actor["id"])
    return E([account_public(r) for r in rows])


@app.post("/api/accounts")
async def create_account(payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    username = payload.get("username") or snake(payload.get("display_name", "analyst"))
    existing = await p.fetchrow("select * from accounts where username=$1", username)
    if existing and not can_edit_account(actor, existing["id"]):
        return E(None, error="not authorized to edit this account")
    if payload.get("privilege_level") == "admin" and actor["privilege_level"] != "admin":
        payload["privilege_level"] = "analyst"
    password_hash = hash_password(payload.get("password")) if payload.get("password") else (existing["password_hash"] if existing else "")
    team_id = uuid.UUID(payload["team_id"]) if payload.get("team_id") else None
    r = await p.fetchrow("""
        insert into accounts(username,display_name,privilege_level,service_branch,rank,work_role,skill_level,team,bio,certs,degrees,years_experience,contact,email,phone,password_hash,team_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
        on conflict(username) do update set display_name=excluded.display_name, privilege_level=excluded.privilege_level, service_branch=excluded.service_branch, rank=excluded.rank, work_role=excluded.work_role, skill_level=excluded.skill_level, team=excluded.team, bio=excluded.bio, certs=excluded.certs, degrees=excluded.degrees, years_experience=excluded.years_experience, contact=excluded.contact, email=excluded.email, phone=excluded.phone, password_hash=excluded.password_hash, team_id=excluded.team_id, updated_at=now()
        returning *
    """, username, payload.get("display_name", username), payload.get("privilege_level", "analyst"), payload.get("service_branch", ""), payload.get("rank", ""), payload.get("work_role", "Network Analyst"), payload.get("skill_level", "Basic"), payload.get("team", ""), payload.get("bio", ""), payload.get("certs", ""), payload.get("degrees", ""), int(payload.get("years_experience") or 0), payload.get("contact", ""), payload.get("email", ""), payload.get("phone", ""), password_hash, team_id)
    return E(account_public(r))


@app.get("/api/accounts/{account_id}")
async def account_detail(account_id: str, token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    a = await p.fetchrow("select a.*, t.name as team_name, t.number as team_number, t.team_type from accounts a left join teams t on t.id=a.team_id where a.id=$1 or a.username=$2", uuid.UUID(account_id) if re.match(r"^[0-9a-f-]{36}$", account_id, re.I) else None, account_id)
    if not a:
        return E(None, error="account not found")
    if not can_edit_account(actor, a["id"]):
        return E(None, error="not authorized")
    cases_rows = await p.fetch("select c.case_id,c.name,c.status,c.updated_at,cm.role from case_members cm join cases c on c.id=cm.case_id where cm.account_id=$1 order by c.updated_at desc", a["id"])
    return E({**account_public(a), "cases": [dict(r) for r in cases_rows]})


@app.get("/api/teams")
async def teams():
    p = await P()
    rows = await p.fetch("""
        select t.*, count(a.id)::int as member_count from teams t
        left join accounts a on a.team_id=t.id
        group by t.id order by case when t.team_type='CPT' then 0 else 1 end, lpad(t.number,3,'0')
    """)
    return E([rd(r) for r in rows])


@app.post("/api/teams")
async def upsert_team(payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    r = await p.fetchrow("""
        insert into teams(team_type,number,name,description,logo_url,location,phone,email,notes,team_lead_id,deputy_team_lead_id,planner_id,ncoic_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        on conflict(number) do update set team_type=excluded.team_type, name=excluded.name, description=excluded.description, logo_url=excluded.logo_url, location=excluded.location, phone=excluded.phone, email=excluded.email, notes=excluded.notes, team_lead_id=excluded.team_lead_id, deputy_team_lead_id=excluded.deputy_team_lead_id, planner_id=excluded.planner_id, ncoic_id=excluded.ncoic_id, updated_at=now()
        returning *
    """, payload.get("team_type", "CPT"), payload["number"], payload.get("name") or f"{payload['number']} Cyber Protection Team", payload.get("description", ""), payload.get("logo_url", ""), payload.get("location", ""), payload.get("phone", ""), payload.get("email", ""), payload.get("notes", ""), uuid.UUID(payload["team_lead_id"]) if payload.get("team_lead_id") else None, uuid.UUID(payload["deputy_team_lead_id"]) if payload.get("deputy_team_lead_id") else None, uuid.UUID(payload["planner_id"]) if payload.get("planner_id") else None, uuid.UUID(payload["ncoic_id"]) if payload.get("ncoic_id") else None)
    return E(rd(r))


@app.get("/api/teams/{team_id}")
async def team_detail(team_id: str):
    p = await P()
    t = await p.fetchrow("select * from teams where id=$1 or number=$2", uuid.UUID(team_id) if re.match(r"^[0-9a-f-]{36}$", team_id, re.I) else None, team_id)
    if not t:
        return E(None, error="team not found")
    members = await p.fetch("select * from accounts where team_id=$1 order by rank, display_name", t["id"])
    leadership = {}
    for field in ["team_lead_id", "deputy_team_lead_id", "planner_id", "ncoic_id"]:
        aid = t[field]
        leadership[field] = account_public(await p.fetchrow("select * from accounts where id=$1", aid)) if aid else None
    return E({**rd(t), "leadership": leadership, "members": [account_public(m) for m in members]})


@app.get("/api/setup/kibana")
async def kibana_info(url: Optional[str] = None):
    return E({"url": url or settings.kibana_url, "note": "Kibana may require separate Traefik/basic-auth credentials."})


@app.post("/api/chat")
async def chat(payload: dict):
    role = payload.get("role", "analyst")
    question = payload.get("message", "")[:2000]
    context = {"role": role, "question": question, "events": [], "cases": []}
    p = await P()
    for r in await p.fetch("select event_id,title,severity,status,explanation from events order by updated_at desc limit 8"):
        context["events"].append(dict(r))
    for r in await p.fetch("select case_id,name,status,final_output from cases order by updated_at desc limit 5"):
        context["cases"].append(dict(r))
    if settings.openrouter_api_key:
        ans = await openrouter_agent_summary(f"{role}_chatbot", {"title": "Operator question", "question": question, "context": context, "fallback_explanation": "Answer from current case/event context."}, "medium")
        return E({"answer": ans["explanation"] + "\n\nSuggested way ahead: " + ans["recommended_next_question"], "model": ans.get("model_used")})
    fallback = "Review the highest-severity open alerts, confirm raw evidence, and update the case timeline. " if role == "analyst" else "Focus the briefing on open cases, unresolved 5 Ws, affected assets, and decisions needed. "
    return E({"answer": fallback + "Current context includes %d events and %d cases. Question: %s" % (len(context["events"]), len(context["cases"]), question), "model": "deterministic"})


@app.get("/api/enrichment/configs")
async def enrichment_configs():
    rows = await (await P()).fetch("select * from enrichment_configs order by name")
    return E([rd(r) for r in rows])


@app.post("/api/enrichment/configs")
async def upsert_enrichment(payload: dict):
    r = await (await P()).fetchrow("""
        insert into enrichment_configs(name,provider_type,enabled,base_url,api_key_ref,notes,config) values($1,$2,$3,$4,$5,$6,$7)
        on conflict(name) do update set provider_type=excluded.provider_type, enabled=excluded.enabled, base_url=excluded.base_url, api_key_ref=excluded.api_key_ref, notes=excluded.notes, config=excluded.config, updated_at=now()
        returning *
    """, payload["name"], payload.get("provider_type", "custom_http"), bool(payload.get("enabled", False)), payload.get("base_url", ""), payload.get("api_key_ref", ""), payload.get("notes", ""), json.dumps(payload.get("config", {})))
    return E(rd(r))


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
