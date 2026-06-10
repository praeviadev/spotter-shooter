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
    kibana_url: str = ""
    smtp_url: str = ""
    sms_webhook_url: str = ""
    twofa_required: bool = False

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
        # Base tables first: later alters reference them.
        "create table if not exists accounts (id uuid primary key default gen_random_uuid(), username text unique not null, display_name text not null, privilege_level text not null default 'analyst', service_branch text default '', rank text default '', work_role text default '', skill_level text default 'basic', team text default '', bio text default '', certs text default '', degrees text default '', years_experience int default 0, contact text default '', created_at timestamptz default now(), updated_at timestamptz default now())",
        "create table if not exists teams (id uuid primary key default gen_random_uuid(), team_type text not null default 'CPT', number text unique not null, name text not null, description text default '', logo_url text default '', location text default '', phone text default '', email text default '', notes text default '', team_lead_id uuid, deputy_team_lead_id uuid, planner_id uuid, ncoic_id uuid, created_at timestamptz default now(), updated_at timestamptz default now())",
        "alter table events add column if not exists agent_summary jsonb default '{}'::jsonb",
        "alter table cases add column if not exists created_by uuid",
        "alter table cases add column if not exists bluf text default ''",
        "alter table cases add column if not exists five_ws jsonb default '{}'::jsonb",
        "alter table cases add column if not exists technical_summary text default ''",
        "alter table cases add column if not exists way_ahead text default ''",
        "alter table cases add column if not exists final_output text default ''",
        "alter table cases add column if not exists priority text default 'medium'",
        "alter table cases add column if not exists how text default ''",
        "alter table cases add column if not exists owner_team_id uuid references teams(id)",
        "alter table case_events add column if not exists added_at timestamptz default now()",
        "alter table case_events add column if not exists added_by uuid",
        "alter table case_events add column if not exists note text default ''",
        "alter table accounts add column if not exists email text default ''",
        "alter table accounts add column if not exists phone text default ''",
        "alter table accounts add column if not exists first_name text default ''",
        "alter table accounts add column if not exists last_name text default ''",
        "alter table accounts add column if not exists password_hash text default ''",
        "alter table accounts add column if not exists team_id uuid",
        "alter table teams add column if not exists team_lead_text text default ''",
        "alter table teams add column if not exists deputy_team_lead_text text default ''",
        "alter table teams add column if not exists planner_text text default ''",
        "alter table teams add column if not exists ncoic_text text default ''",
        "create table if not exists auth_sessions (token text primary key, account_id uuid references accounts(id) on delete cascade, created_at timestamptz default now(), expires_at timestamptz not null)",
        "alter table auth_sessions add column if not exists last_seen_at timestamptz default now()",
        "alter table auth_sessions add column if not exists current_view text default ''",
        "create table if not exists app_settings (key text primary key, value jsonb not null default '{}'::jsonb, updated_at timestamptz default now())",
        "insert into app_settings(key,value) values ('security', jsonb_build_object('twofa_required', false, 'smtp_url_configured', false, 'sms_webhook_url_configured', false)) on conflict(key) do nothing",
        "insert into app_settings(key,value) values ('kibana', jsonb_build_object('url', '')) on conflict(key) do nothing",
        "create table if not exists login_challenges (id uuid primary key default gen_random_uuid(), account_id uuid references accounts(id) on delete cascade, code_hash text not null, destination text default '', method text default 'email', expires_at timestamptz not null, used_at timestamptz, created_at timestamptz default now())",
        "create table if not exists case_members (case_id uuid references cases(id) on delete cascade, account_id uuid references accounts(id) on delete cascade, role text default 'supporting analyst', joined_at timestamptz default now(), primary key(case_id, account_id))",
        "create table if not exists case_indicators (id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade, indicator_type text not null, value text not null, source text default 'analyst', description text default '', created_by uuid references accounts(id), created_at timestamptz default now(), unique(case_id, indicator_type, value))",
        "create table if not exists case_timeline (id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade, event_time timestamptz default now(), entry_type text not null default 'note', title text not null, body text default '', actor_id uuid references accounts(id), actor_name text default '', related_event_id text, related_indicator text, created_at timestamptz default now())",
        "create table if not exists enrichment_configs (id uuid primary key default gen_random_uuid(), name text unique not null, provider_type text not null, enabled boolean default false, base_url text default '', api_key_ref text default '', notes text default '', config jsonb default '{}'::jsonb, created_at timestamptz default now(), updated_at timestamptz default now())",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('Local OpenCTI','opencti',false,'http://opencti:8080','Local OpenCTI enrichment. Configure URL/token before enabling.', '{\"token_env\":\"OPENCTI_TOKEN\"}'::jsonb) on conflict(name) do nothing",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('VirusTotal','virustotal',false,'https://www.virustotal.com/api/v3','Optional cloud enrichment. Disabled by default; requires API key.', '{\"api_key_env\":\"VIRUSTOTAL_API_KEY\"}'::jsonb) on conflict(name) do nothing",
        "insert into enrichment_configs(name, provider_type, enabled, base_url, notes, config) values ('Custom HTTP Enrichment','custom_http',false,'','Operator-defined HTTP enrichment endpoint. Disabled by default.', '{}'::jsonb) on conflict(name) do nothing",
        "create table if not exists password_resets (id uuid primary key default gen_random_uuid(), account_id uuid references accounts(id) on delete cascade, code_hash text not null, delivered_to text default '', method text default 'email', expires_at timestamptz not null, used_at timestamptz, created_at timestamptz default now())",
        "create table if not exists notifications (id uuid primary key default gen_random_uuid(), recipient_id uuid references accounts(id) on delete cascade, sender_id uuid references accounts(id) on delete set null, n_type text default 'info', body text default '', case_id uuid references cases(id) on delete cascade, event_id text, read_at timestamptz, created_at timestamptz default now())",
        "create table if not exists audit_trail (id uuid primary key default gen_random_uuid(), actor_id uuid references accounts(id) on delete set null, action text default '', target_type text default '', target_id text default '', details jsonb default '{}'::jsonb, created_at timestamptz default now())",
        "create table if not exists attck_mappings (id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade, technique_id text not null, technique_name text default '', evidence text default '', created_by uuid references accounts(id) on delete set null, created_at timestamptz default now())",
        "create table if not exists saved_pivots (id uuid primary key default gen_random_uuid(), name text default '', description text default '', query text default '', dsl jsonb default '{}'::jsonb, index_pattern text default '', time_range text default '', created_by uuid references accounts(id) on delete set null, owner_id uuid references accounts(id) on delete cascade, shared boolean default false, created_at timestamptz default now())",
        "create table if not exists case_teams (case_id uuid references cases(id) on delete cascade, team_id uuid references teams(id) on delete cascade, added_by uuid references accounts(id) on delete set null, added_at timestamptz default now(), primary key(case_id, team_id))",
        "create table if not exists case_acl (case_id uuid references cases(id) on delete cascade, entity_type text not null, entity_id uuid not null, granted_by uuid references accounts(id) on delete set null, granted_at timestamptz default now(), primary key(case_id, entity_type, entity_id))",
        "create table if not exists messages (id uuid primary key default gen_random_uuid(), sender_id uuid references accounts(id) on delete cascade, recipient_id uuid references accounts(id) on delete cascade, body text default '', read_at timestamptz, created_at timestamptz default now())",
        "create table if not exists chat_history (id uuid primary key default gen_random_uuid(), token text not null, role text not null default 'analyst', seq int not null default 0, message text not null, answer text not null, created_at timestamptz default now())",
        "create table if not exists signatures (id uuid primary key default gen_random_uuid(), name text not null, description text default '', field text default '', value text not null, severity text default 'medium', enabled boolean default true, created_by uuid references accounts(id) on delete cascade, created_by_name text default '', last_total bigint default -1, last_run_at timestamptz, last_hit_at timestamptz, created_at timestamptz default now(), updated_at timestamptz default now())",
        "create table if not exists agent_state (agent text primary key, last_total bigint default -1, last_run_at timestamptz, details jsonb default '{}'::jsonb)",
        "create table if not exists failed_logins (id uuid primary key default gen_random_uuid(), account_id uuid references accounts(id) on delete cascade, username text default '', created_at timestamptz default now())",
        """insert into teams(team_type,number,name) values ('CPT','100','100 Cyber Protection Team'),('CPT','101','101 Cyber Protection Team'),('CPT','150','150 Cyber Protection Team'),('CPT','151','151 Cyber Protection Team'),('CPT','152','152 Cyber Protection Team'),('CPT','153','153 Cyber Protection Team'),('CPT','154','154 Cyber Protection Team'),('CPT','155','155 Cyber Protection Team'),('CPT','156','156 Cyber Protection Team'),('CPT','200','200 Cyber Protection Team'),('CPT','201','201 Cyber Protection Team'),('CPT','400','400 Cyber Protection Team'),('CPT','401','401 Cyber Protection Team'),('CPT','600','600 Cyber Protection Team'),('CPT','503','503 Cyber Protection Team'),('NCPT','01','01 National Cyber Protection Team'),('NCPT','03','03 National Cyber Protection Team'),('NCPT','05','05 National Cyber Protection Team'),('NCPT','23','23 National Cyber Protection Team') on conflict(number) do nothing""",
    ]
    async with db.acquire() as conn:
        for stmt in stmts:
            await conn.execute(stmt)


RANKS = {
    "army": ["CIV", "PVT", "PV2", "PFC", "SPC", "CPL", "SGT", "SSG", "SFC", "MSG", "1SG", "SGM", "CSM", "SMA", "WO1", "CW2", "CW3", "CW4", "CW5", "2LT", "1LT", "CPT", "MAJ", "LTC", "COL", "BG", "MG", "LTG", "GEN"],
    "airforce": ["CIV", "AB", "Amn", "A1C", "SrA", "SSgt", "TSgt", "MSgt", "SMSgt", "CMSgt", "CCM", "CMSAF", "2d Lt", "1st Lt", "Capt", "Maj", "Lt Col", "Col", "Brig Gen", "Maj Gen", "Lt Gen", "Gen"],
    "coastguard": ["CIV", "SR", "SA", "SN", "PO3", "PO2", "PO1", "CPO", "SCPO", "MCPO", "CMC", "MCPOCG", "ENS", "LTJG", "LT", "LCDR", "CDR", "CAPT", "RDML", "RADM", "VADM", "ADM"],
    "navy": ["CIV", "SR", "SA", "SN", "PO3", "PO2", "PO1", "CPO", "SCPO", "MCPO", "CMC", "MCPON", "ENS", "LTJG", "LT", "LCDR", "CDR", "CAPT", "RDML", "RADM", "VADM", "ADM", "FADM"],
    "marines": ["CIV", "Pvt", "PFC", "LCpl", "Cpl", "Sgt", "SSgt", "GySgt", "MSgt", "1stSgt", "MGySgt", "SgtMaj", "SMMC", "WO", "CWO2", "CWO3", "CWO4", "CWO5", "2ndLt", "1stLt", "Capt", "Maj", "LtCol", "Col", "BGen", "MajGen", "LtGen", "Gen"],
}
WORK_ROLES = ["Analytic Support Officer", "Data Engineer", "Host Analyst", "Network Analyst", "Planner", "Cyber Integration Technician", "Master Gunner", "Team Lead", "Deputy Team Lead", "NCOIC", "Commander"]
SKILL_LEVELS = ["Basic", "Senior", "Master"]
PRIVILEGE_LEVELS = ["analyst", "commander", "admin"]
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


async def session_actor(p, token: str):
    """Strict session lookup: returns the account only for a valid, unexpired session token."""
    if not token:
        return None
    return await p.fetchrow("select a.* from auth_sessions s join accounts a on a.id=s.account_id where s.token=$1 and s.expires_at>now()", token)


async def get_actor(p, token: str = ""):
    row = await session_actor(p, token)
    if row:
        return row
    return await ensure_default_account(p)


def account_public(r):
    d = rd(r)
    d.pop("password_hash", None)
    d["formatted_name"] = format_person(r)
    if d.get("team_name") or d.get("name") or d.get("team_number") or d.get("number"):
        d["team_display"] = team_display(d)
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


async def get_setting(p, key: str, default=None):
    row = await p.fetchrow("select value from app_settings where key=$1", key)
    if not row:
        return default if default is not None else {}
    value = row["value"]
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default if default is not None else {}
    return value or (default if default is not None else {})


async def upsert_setting(p, key: str, value: dict):
    return await p.fetchrow("insert into app_settings(key,value,updated_at) values($1,$2::jsonb,now()) on conflict(key) do update set value=excluded.value, updated_at=now() returning *", key, json.dumps(value))


async def audit(p, actor_id, action: str, target_type: str = "", target_id: str = "", details: dict = None):
    """Best-effort server-side audit entry; never blocks the calling action."""
    try:
        await p.execute(
            "insert into audit_trail(actor_id,action,target_type,target_id,details) values($1,$2,$3,$4,$5)",
            actor_id, action, target_type, str(target_id or ""), json.dumps(details or {}),
        )
    except Exception:
        pass


async def security_config(p):
    cfg = await get_setting(p, "security", {})
    return {
        "twofa_required": bool(cfg.get("twofa_required", settings.twofa_required)),
        "smtp_url_configured": bool(settings.smtp_url or cfg.get("smtp_url_configured")),
        "sms_webhook_url_configured": bool(settings.sms_webhook_url or cfg.get("sms_webhook_url_configured")),
    }


async def kibana_config(p):
    cfg = await get_setting(p, "kibana", {})
    return {"url": (cfg.get("url") or settings.kibana_url or "").strip()}


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
    return FileResponse(FRONTEND / "operations.html")


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
            "who": "", "what": "", "when": "", "where": "", "why": "", "how": "",
        }
    prompt = {
        "agent": agent,
        "severity": severity,
        "evidence": evidence,
        "task": "Return concise JSON with keys title, explanation, recommended_next_question, confidence. Also include: who (threat actor identity or compromised user account, or unknown), what (MITRE ATT&CK technique ID and technique name, e.g. T1047 Windows Management Instrumentation), where (host name or IP address), why (attacker intent or operational objective), how (how did the attacker gain initial access: misconfiguration, CVE exploitation, credential compromise, social engineering, living-off-the-land, etc.). When available populate attacker-facing fields (who, what, where, why, how); otherwise use 'not yet determined'. Make the response read like a professional SOC analyst brief. Do not invent facts outside evidence."
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
            "who": str(data.get("who", ""))[:300],
            "what": str(data.get("what", ""))[:300],
            "when": str(data.get("when", ""))[:200],
            "where": str(data.get("where", ""))[:300],
            "why": str(data.get("why", ""))[:400],
            "how": str(data.get("how", ""))[:400],
        }
    except Exception as exc:
        msg = str(exc)[:220] or exc.__class__.__name__
        return {
            "title": evidence.get("title") or f"{agent} Finding",
            "explanation": (evidence.get("fallback_explanation") or "Model call failed; deterministic finding generated from live telemetry.") + f" Model error: {exc.__class__.__name__}: {msg}",
            "recommended_next_question": "Review the raw evidence and retry the model-backed agent test if needed.",
            "confidence": 0.40,
            "model_used": "error",
            "who": "", "what": "", "when": "", "where": "", "why": "", "how": "",
        }


@app.get("/static/{filename}")
async def static_files(filename: str):
    safe = Path(filename).name
    path = FRONTEND / "static" / safe
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".webp"} and path.exists():
        return FileResponse(path)
    return HTMLResponse(status_code=404, content="not found")


@app.get("/favicon.ico")
async def favicon():
    path = FRONTEND / "static" / "logo.png"
    if path.exists():
        return FileResponse(path)
    return HTMLResponse(status_code=404, content="not found")


@app.get("/admin.html")
async def admin():
    return FileResponse(FRONTEND / "admin.html")


@app.get("/search.html")
async def search_page():
    return FileResponse(FRONTEND / "search.html")


@app.get("/api/admin/accounts")
async def admin_list_accounts(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    rows = await p.fetch("select a.*, t.name as team_name, t.number as team_number, t.team_type, t.id as team_id from accounts a left join teams t on t.id=a.team_id order by a.display_name")
    return E([account_public(r) for r in rows])


@app.get("/api/admin/teams-full")
async def admin_list_teams_full(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    rows = await p.fetch("select t.*, (select count(*) from accounts where team_id=t.id) as member_count from teams t order by t.number, t.team_type")
    return E([rd(r) for r in rows])


@app.get("/api/health")
async def health():
    es_ok = await ok_http(settings.elasticsearch_url)
    s = {
        "Postgres": await ok_pg(),
        "Redis": await ok_redis(),
        "Elasticsearch": es_ok,
        "Qdrant": await ok_http(settings.qdrant_url + "/healthz"),
        "MinIO": await ok_http("http://" + settings.minio_endpoint + "/minio/health/live"),
        "Model Route (OpenRouter)": bool(settings.openrouter_api_key),
        "Zeek": bool(shutil.which("zeek") or Path("/var/run/docker.sock").exists()),
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
    ("Signature Match Agent", "signature_agent", "Analyst signatures", "network", True),
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


def normalize_person_name(payload: dict) -> tuple[str, str, str]:
    first = (payload.get("first_name") or payload.get("first") or "").strip()
    last = (payload.get("last_name") or payload.get("last") or "").strip()
    display = (payload.get("display_name") or "").strip()
    # Backwards-compatible parse for the old single Display Name field.
    if (not first or not last) and display:
        parts = display.split()
        if not first and len(parts) >= 2:
            first = parts[0]
        if not last and len(parts) >= 2:
            last = " ".join(parts[1:])
    if not display:
        display = " ".join(x for x in [last, first] if x).strip()
    return first, last, display or (payload.get("username") or "analyst")


def format_person(row) -> str:
    d = dict(row)
    rank = (d.get("rank") or "").strip()
    first = (d.get("first_name") or "").strip()
    last = (d.get("last_name") or "").strip()
    display = (d.get("display_name") or "").strip()
    # If legacy records only have display_name like "Terry Smith", render as Last First.
    if (not first and not last) and display:
        parts = display.split()
        if len(parts) >= 2:
            first = parts[0]
            last = " ".join(parts[1:])
    core = " ".join(x for x in [last, first] if x).strip() or display
    return " ".join(x for x in [rank, core] if x).strip() or display or (d.get("username") or "Analyst")


def team_display(row) -> str:
    d = dict(row)
    typ = (d.get("team_type") or "").strip().upper()
    num = (d.get("team_number") or d.get("number") or "").strip()
    name = (d.get("team_name") or d.get("name") or "").strip()
    if not num:
        m = re.match(r"^(\d+)\s+(?:National\s+)?Cyber\s+Protection\s+Team$", name, re.I)
        if m:
            num = m.group(1)
    if not typ and "national" in name.lower():
        typ = "NCPT"
    base = "National Cyber Protection Team" if typ == "NCPT" else "Cyber Protection Team"
    if num:
        return f"{num} {base}"
    return f"Team Number Required {base}"


def team_public(r):
    d = rd(r)
    d["team_display"] = team_display(d)
    return d


async def require_admin_from_token(p, token: str):
    if not token:
        return None
    row = await p.fetchrow("select a.* from auth_sessions s join accounts a on a.id=s.account_id where s.token=$1 and s.expires_at>now()", token)
    return row if row and row["privilege_level"] == "admin" else None


async def can_access_case(p, case_id: str, actor) -> bool:
    """Check if an account has access to a case. Permissions: admin, commander role, same team as owner, explicitly granted team, or case member."""
    if not actor:
        return False
    if actor["privilege_level"] in ("admin", "commander"):
        return True
    # Commander work-role access
    work_role = (actor.get("work_role") or "").lower()
    if "commander" in work_role:
        return True
    # Case member access
    is_member = await p.fetchrow(
        "select 1 from case_members cm where cm.case_id=$1 and cm.account_id=$2",
        case_id, actor["id"]
    )
    if is_member:
        return True
    # Same team as case owner
    owner_team = await p.fetchval("select team_id from accounts where id=$1", actor["id"])
    if owner_team:
        case_owner_team = await p.fetchval("select owner_team_id from cases where id=$1", case_id)
        if case_owner_team and owner_team == case_owner_team:
            return True
    # Explicitly granted team
    actor_team_id = actor.get("team_id")
    if actor_team_id:
        team_grant = await p.fetchrow(
            "select 1 from case_teams where case_id=$1 and team_id=$2",
            case_id, actor_team_id
        )
        if team_grant:
            return True
    # ACL grants (for future per-entity grants)
    acl_grant = await p.fetchrow(
        "select 1 from case_acl where case_id=$1 and ((entity_type='account' AND entity_id=$2) OR (entity_type='team' AND entity_id=$3))",
        case_id, actor["id"], actor.get("team_id")
    )
    if acl_grant:
        return True
    return False


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
        # Discover ALL indices; hide system/internal ones (dot-prefixed) from the operator.
        cat = await es_request("GET", "/_cat/indices?format=json&h=index,docs.count,health", base_url=configured, username=username, password=password)
        indexes = sorted(
            [{"index": x.get("index"), "docs": int(x.get("docs.count") or 0), "health": x.get("health")} for x in cat if x.get("index") and not x["index"].startswith(".")],
            key=lambda x: -x["docs"],
        )
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
        cat = await es_request("GET", "/_cat/indices?format=json&h=index,docs.count,health")
        sources = sorted(
            [{"name": x.get("index"), "count": int(x.get("docs.count") or 0), "health": x.get("health")} for x in cat if x.get("index") and not x["index"].startswith(".")],
            key=lambda x: -x["count"],
        )
        total = sum(s["count"] for s in sources)
        return E({"sources": sources, "total_docs": total, "recommendation": "Telemetry detected. Start with network agents, then add host agents for confirmed pivots."})
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
    return E([team_public(r) for r in rows])


@app.get("/api/events")
async def events(limit: int = 100, session_id: Optional[str] = None):
    p = await P()
    if session_id and session_id != "demo":
        rows = await p.fetch("select * from events where session_id=$1 order by created_at desc limit $2", uuid.UUID(session_id), limit)
    else:
        rows = await p.fetch("select * from events order by created_at desc limit $1", limit)
    return E([ev(r) for r in rows])


@app.patch("/api/events/{event_id}/dismiss")
async def dismiss(event_id: str, token: str = ""):
    p = await P()
    actor = await session_actor(p, token)
    if not actor:
        return E(None, error="login required to triage alerts")
    await p.execute("update events set status='dismissed', updated_at=now() where event_id=$1", event_id)
    await audit(p, actor["id"], "alert_dismissed", "event", event_id)
    return E({"event_id": event_id, "status": "dismissed"})


async def ensure_default_account(p):
    row = await p.fetchrow("select * from accounts order by created_at limit 1")
    if row:
        return row
    return await p.fetchrow("insert into accounts(username,display_name,first_name,last_name,privilege_level,work_role,skill_level,team,bio) values('analyst','Analyst','Analyst','','analyst','Network Analyst','Basic','','Default analyst profile') returning *")


async def build_case_final(p, case_uuid):
    c = await p.fetchrow("select * from cases where id=$1", case_uuid)
    members = await p.fetch("select a.display_name,a.rank,a.service_branch,a.work_role,a.skill_level,a.team,cm.role from case_members cm join accounts a on a.id=cm.account_id where cm.case_id=$1 order by cm.joined_at", case_uuid)
    events = await p.fetch("select e.* from case_events ce join events e on e.id=ce.event_id where ce.case_id=$1 order by ce.added_at", case_uuid)
    inds = await p.fetch("select indicator_type,value from case_indicators where case_id=$1 order by created_at", case_uuid)
    lead = "; ".join([f"{format_person(m)} ({m['work_role']}, {m['skill_level']}, {m['team']})".strip() for m in members]) or c["owner"]
    sev = events[0]["severity"] if events else "medium"
    titles = "; ".join([e["title"] for e in events[:5]]) or c["name"]
    indicators = ", ".join([f"{i['indicator_type']}:{i['value']}" for i in inds[:12]]) or "none confirmed"
    bluf = c["bluf"] or f"BLUF/SO WHAT: {sev.upper()} case {c['case_id']} requires analyst action because correlated alerts indicate {c['name']}."
    # Try to extract who/what/when/where/why/how from event agent_summary fields
    extracted = {}
    extracted_how = ""
    for ev in events:
        ag = _jsonish(ev.get("agent_summary"))
        if ag:
            for k in ("who","what","when","where","why","how"):
                if k in ag and ag[k]:
                    extracted[k] = ag[k]
        # Also check fields directly on the event row
        for k in ("who","what","when","where","why","how"):
            v = ev.get(k)
            if v and k not in extracted:
                extracted[k] = v
        if "how" in ag and ag["how"] and not extracted_how:
            extracted_how = ag["how"]

    five_ws = _jsonish(c["five_ws"])
    how_val = c.get("how", "") or extracted_how
    if not isinstance(five_ws, dict) or not five_ws:
        # Derive when range from events
        when_first = None
        when_last = None
        for ev in events:
            ts = ev.get("created_at") or ev.get("occurred_at")
            if ts:
                ts_str = ser(ts)
                when_first = ts_str if not when_first else min(when_first, ts_str)
                when_last = ts_str if not when_last else max(when_last, ts_str)
        when_range = when_first if not when_last else f"{when_first} → {when_last}"

        five_ws = {
            "who": extracted.get("who", "Unknown threat actor; compromised user not yet identified from telemetry"),
            "what": extracted.get("what", f"{titles} — correlate with MITRE ATT&CK techniques and event details above"),
            "when": extracted.get("when", when_range or ser(c["created_at"])),
            "where": extracted.get("where", f"IP address or host name: {indicators} — verify workstation names, department, and network segment context"),
            "why": extracted.get("why", "Attacker intent not yet determined — review for data theft, persistence, lateral movement, or disruption objectives"),
        }
        if not how_val:
            how_val = extracted.get("how", "Initial access vector not yet determined — review for misconfiguration, social engineering, CVE exploitation, credential compromise, or living-off-the-land techniques")
    technical = c["technical_summary"] or c["narrative_summary"] or "Technical summary pending analyst validation."
    way = c["way_ahead"] or "Validate indicators, pivot across related telemetry, request network-owner context, scope affected assets/users, and decide containment/reporting actions."
    final = f"{bluf}\n\n5 Ws:\n- Who: {five_ws.get('who','')}\n- What: {five_ws.get('what','')}\n- When: {five_ws.get('when','')}\n- Where: {five_ws.get('where','')}\n- Why: {five_ws.get('why','')}\n\nHow: {how_val or 'Not yet determined'}\n\nTechnical Summary:\n{technical}\n\nWay Ahead:\n{way}\n\nAnalyst / Work Role:\n{lead}"
    await p.execute("update cases set bluf=$2,five_ws=$3,technical_summary=$4,way_ahead=$5,final_output=$6,how=$7,updated_at=now() where id=$1", case_uuid, bluf, json.dumps(five_ws), technical, way, final, how_val)
    return final


@app.patch("/api/events/{event_id}/escalate")
async def escalate(event_id: str, payload: dict = {}):
    p = await P()
    # Attribution: the logged-in session wins; explicit actor_id only as a fallback for API callers.
    actor = await session_actor(p, (payload or {}).get("token", ""))
    if not actor:
        actor_id = payload.get("actor_id") if payload else None
        actor = await p.fetchrow("select * from accounts where id=$1", uuid.UUID(actor_id)) if actor_id else None
    if not actor:
        return E(None, error="login required to escalate alerts")
    e = await p.fetchrow("select * from events where event_id=$1", event_id)
    cid = "CASE-" + event_id.split("-")[-1]
    if not e:
        return E({"case_id": cid}, error="event not found")
    case = await p.fetchrow("select * from cases where case_id=$1", cid)
    if not case:
        case = await p.fetchrow(
            "insert into cases(case_id,session_id,name,owner,narrative_summary,ioc_tags,status,created_by,owner_team_id) values($1,$2,$3,$4,$5,'[]'::jsonb,'open',$6,$7) returning *",
            cid, e["session_id"], e["title"], actor["display_name"], e["explanation"], actor["id"], actor.get("team_id"),
        )
    await p.execute("insert into case_events(case_id,event_id,added_by,note) values($1,$2,$3,$4) on conflict(case_id,event_id) do update set added_at=now(), added_by=excluded.added_by", case["id"], e["id"], actor["id"], "Escalated from alert")
    await p.execute("insert into case_members(case_id,account_id,role) values($1,$2,$3) on conflict(case_id,account_id) do update set role=excluded.role", case["id"], actor["id"], actor["work_role"] or "analyst")
    await p.execute("update events set status='escalated', suggested_case_link=$2, updated_at=now() where event_id=$1", event_id, case["id"])
    await p.execute("insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name,related_event_id) values($1,'alert','Alert escalated',$2,$3,$4,$5)", case["id"], e["title"], actor["id"], actor["display_name"], event_id)
    for ind in extract_indicators_from_event(e):
        await p.execute("insert into case_indicators(case_id,indicator_type,value,source,description,created_by) values($1,$2,$3,'alert',$4,$5) on conflict(case_id,indicator_type,value) do nothing", case["id"], ind["type"], ind["value"], event_id, actor["id"])
    await build_case_final(p, case["id"])
    await audit(p, actor["id"], "alert_escalated", "case", case["case_id"], {"event_id": event_id})
    return E({"case_id": case["case_id"], "case_uuid": str(case["id"]), "status": "open"})


def case_obj(r, event_count=0, member_count=0):
    return {
        "uuid": ser(r["id"]), "id": r["case_id"], "case_id": r["case_id"], "name": r["name"], "owner": r["owner"],
        "summary": r["narrative_summary"], "status": r["status"], "iocs": _jsonish(r["ioc_tags"]), "opened": ser(r["created_at"]),
        "updated_at": ser(r["updated_at"]), "events": event_count, "members": member_count, "bluf": r["bluf"],
        "five_ws": _jsonish(r["five_ws"]), "technical_summary": r["technical_summary"], "way_ahead": r["way_ahead"], "final_output": r["final_output"], "how": r.get("how", "") or "",
        "owner_team_id": ser(r.get("owner_team_id")),
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
async def case_detail(case_id: str, token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    c = await p.fetchrow("select * from cases where case_id=$1 or id::text=$1", case_id)
    if not c:
        return E(None, error="case not found")
    if not await can_access_case(p, c["id"], actor):
        return E(None, error="access denied: case restricted to case members, owner team members, commanders, or admins")
    events_rows = await p.fetch("select e.* from case_events ce join events e on e.id=ce.event_id where ce.case_id=$1 order by ce.added_at desc", c["id"])
    members = await p.fetch("select a.*, cm.role, cm.joined_at from case_members cm join accounts a on a.id=cm.account_id where cm.case_id=$1 order by cm.joined_at", c["id"])
    indicators = await p.fetch("select * from case_indicators where case_id=$1 order by created_at desc", c["id"])
    timeline = await p.fetch("select * from case_timeline where case_id=$1 order by event_time desc, created_at desc", c["id"])
    related = {}
    for ind in indicators:
        related[ind["value"]] = await indicator_related(p, ind["value"])
    return E({**case_obj(c, len(events_rows), len(members)), "events": [ev(e) for e in events_rows], "members": [account_public(m) for m in members], "indicators": [rd(i) for i in indicators], "timeline": [rd(t) for t in timeline], "indicator_related": related})


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
    for key in ["bluf", "technical_summary", "way_ahead", "how", "status"]:
        if key in payload:
            vals.append(payload[key]); fields.append(f"{key}=${len(vals)}")
    if "five_ws" in payload:
        vals.append(json.dumps(payload["five_ws"])); fields.append(f"five_ws=${len(vals)}")
    if fields:
        vals.append(c["id"])
        await p.execute(f"update cases set {', '.join(fields)}, updated_at=now() where id=${len(vals)}", *vals)
    if "status" in payload and payload["status"] != c["status"]:
        actor = await session_actor(p, payload.get("token", ""))
        await p.execute(
            "insert into case_timeline(case_id,entry_type,title,body,actor_id,actor_name) values($1,'status',$2,$3,$4,$5)",
            c["id"], f"Status changed to {payload['status']}", f"{c['status']} → {payload['status']}",
            actor["id"] if actor else None, actor["display_name"] if actor else "system",
        )
        await audit(p, actor["id"] if actor else None, "case_status_changed", "case", c["case_id"], {"from": c["status"], "to": payload["status"]})
    final = await build_case_final(p, c["id"])
    return E({"case_id": c["case_id"], "final_output": final})


@app.get("/api/accounts/options")
async def account_options():
    return E({"ranks": RANKS, "work_roles": WORK_ROLES, "skill_levels": SKILL_LEVELS, "privilege_levels": PRIVILEGE_LEVELS, "team_roles": TEAM_ROLES})


@app.get("/api/auth/me")
async def auth_me(token: str = ""):
    p = await P()
    actor = await session_actor(p, token)
    if not actor:
        return E({"authenticated": False, "read_only": True, "account": None, "message": "Read-only view. Please login or Create an Account."})
    # Loading any page while logged in counts as presence.
    await p.execute("update auth_sessions set last_seen_at=now() where token=$1", token)
    return E({"authenticated": True, "read_only": False, "account": account_public(actor), "message": "Authenticated"})


@app.post("/api/auth/login")
async def auth_login(payload: dict):
    p = await P()
    username = payload.get("username", "")
    password = payload.get("password", "")
    method = payload.get("method", "email")
    a = await p.fetchrow("select * from accounts where username=$1 or email=$1 or phone=$1", username)
    if a:
        recent_failures = await p.fetchval("select count(*) from failed_logins where account_id=$1 and created_at>now()-interval '10 minutes'", a["id"])
        if int(recent_failures or 0) >= 5:
            await audit(p, a["id"], "login_locked", "account", a["username"])
            return E(None, error="account temporarily locked after repeated failed logins; try again in 10 minutes")
    if not a or not verify_password(password, a["password_hash"]):
        if a:
            await p.execute("insert into failed_logins(account_id,username) values($1,$2)", a["id"], a["username"])
            await audit(p, a["id"], "login_failed", "account", a["username"])
        return E(None, error="invalid username/password")
    await p.execute("delete from failed_logins where account_id=$1", a["id"])
    await audit(p, a["id"], "login_success", "account", a["username"])
    sec = await security_config(p)
    if not sec["twofa_required"]:
        token = secrets.token_urlsafe(32)
        await p.execute("insert into auth_sessions(token,account_id,expires_at,last_seen_at,current_view) values($1,$2,now()+interval '12 hours',now(),$3)", token, a["id"], "login")
        return E({"token": token, "account": account_public(a), "twofa_required": False})
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
    await p.execute("insert into auth_sessions(token,account_id,expires_at,last_seen_at,current_view) values($1,$2,now()+interval '12 hours',now(),$3)", token, ch["account_id"], "login")
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
    # Strict session: an anonymous request must never inherit the default/first account's privileges.
    actor = await session_actor(p, payload.get("token", ""))
    username = payload.get("username") or snake(payload.get("display_name", "analyst"))
    existing = await p.fetchrow("select * from accounts where username=$1", username)
    if existing and not can_edit_account(actor, existing["id"]):
        return E(None, error="not authorized to edit this account")
    if payload.get("privilege_level") not in PRIVILEGE_LEVELS:
        payload["privilege_level"] = "analyst"
    if payload.get("privilege_level") in ("admin", "commander") and (not actor or actor["privilege_level"] != "admin"):
        payload["privilege_level"] = "analyst"
    first_name, last_name, display_name = normalize_person_name(payload)
    password_hash = hash_password(payload.get("password")) if payload.get("password") else (existing["password_hash"] if existing else "")
    team_id = uuid.UUID(payload["team_id"]) if payload.get("team_id") else None
    r = await p.fetchrow("""
        insert into accounts(username,display_name,first_name,last_name,privilege_level,service_branch,rank,work_role,skill_level,team,bio,certs,degrees,years_experience,contact,email,phone,password_hash,team_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        on conflict(username) do update set display_name=excluded.display_name, first_name=excluded.first_name, last_name=excluded.last_name, privilege_level=excluded.privilege_level, service_branch=excluded.service_branch, rank=excluded.rank, work_role=excluded.work_role, skill_level=excluded.skill_level, team=excluded.team, bio=excluded.bio, certs=excluded.certs, degrees=excluded.degrees, years_experience=excluded.years_experience, contact=excluded.contact, email=excluded.email, phone=excluded.phone, password_hash=excluded.password_hash, team_id=excluded.team_id, updated_at=now()
        returning *
    """, username, display_name, first_name, last_name, payload.get("privilege_level", "analyst"), payload.get("service_branch", ""), payload.get("rank", ""), payload.get("work_role", "Network Analyst"), payload.get("skill_level", "Basic"), payload.get("team", ""), payload.get("bio", ""), payload.get("certs", ""), payload.get("degrees", ""), int(payload.get("years_experience") or 0), payload.get("contact", ""), payload.get("email", ""), payload.get("phone", ""), password_hash, team_id)
    return E(account_public(r))


@app.get("/api/accounts/{account_id}")
async def account_detail(account_id: str, token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    a = await p.fetchrow("select a.*, t.name as team_name, t.number as team_number, t.team_type from accounts a left join teams t on t.id=a.team_id where a.id=$1 or a.username=$2", uuid.UUID(account_id) if re.match(r"^[0-9a-f-]{36}$", account_id, re.I) else None, account_id)
    if not a:
        return E(None, error="account not found")
    cases_rows = await p.fetch("select c.case_id,c.name,c.status,c.updated_at,cm.role from case_members cm join cases c on c.id=cm.case_id where cm.account_id=$1 order by c.updated_at desc", a["id"])
    return E({**account_public(a), "cases": [dict(r) for r in cases_rows]})


@app.post("/api/accounts/self-edit")
async def self_edit_account(payload: dict):
    """Non-admin users can edit their own profile only."""
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    if not actor:
        return E(None, error="must be authenticated")
    # Analysts cannot change privilege level
    payload["privilege_level"] = actor["privilege_level"]
    first_name, last_name, display_name = normalize_person_name(payload)
    password_hash = hash_password(payload.get("password")) if payload.get("password") else actor.get("password_hash", "")
    team_id = uuid.UUID(payload["team_id"]) if payload.get("team_id") else None
    r = await p.fetchrow("""
        update accounts
        set first_name=$1, last_name=$2, display_name=$3, service_branch=$4, rank=$5,
            work_role=$6, skill_level=$7, team=$8, bio=$9, certs=$10, degrees=$11,
            years_experience=$12, contact=$13, email=$14, phone=$15,
            team_id=$16, updated_at=now(), password_hash=case when length($17)>0 then $17 else password_hash end
        where id=$18 returning *
    """, first_name, last_name, display_name or actor["display_name"],
        payload.get("service_branch",""), payload.get("rank",""),
        payload.get("work_role",""), payload.get("skill_level",""),
        payload.get("team",""), payload.get("bio",""), payload.get("certs",""),
        payload.get("degrees",""), int(payload.get("years_experience") or 0),
        payload.get("contact",""), payload.get("email",""), payload.get("phone",""),
        team_id, password_hash if password_hash and payload.get("password") else "", actor["id"])
    return E(account_public(r) if r else None)

@app.delete("/api/accounts/{account_id}")
async def delete_account(account_id: str, token: str = ""):
    p = await P()
    actor = await require_admin_from_token(p, token)
    if not actor:
        return E(None, error="admin required")
    a = await p.fetchrow("select * from accounts where id=$1 or username=$2", uuid.UUID(account_id) if re.match(r"^[0-9a-f-]{36}$", account_id, re.I) else None, account_id)
    if not a:
        return E(None, error="account not found")
    if str(a["id"]) == str(actor["id"]):
        return E(None, error="cannot delete your own active admin account")
    await p.execute("update teams set team_lead_id=null where team_lead_id=$1", a["id"])
    await p.execute("update teams set deputy_team_lead_id=null where deputy_team_lead_id=$1", a["id"])
    await p.execute("update teams set planner_id=null where planner_id=$1", a["id"])
    await p.execute("update teams set ncoic_id=null where ncoic_id=$1", a["id"])
    await p.execute("update cases set created_by=null where created_by=$1", a["id"])
    await p.execute("update case_timeline set actor_id=null where actor_id=$1", a["id"])
    await p.execute("update case_indicators set created_by=null where created_by=$1", a["id"])
    await p.execute("delete from case_members where account_id=$1", a["id"])
    await p.execute("delete from login_challenges where account_id=$1", a["id"])
    await p.execute("delete from auth_sessions where account_id=$1", a["id"])
    # Newer feature tables; existing databases may carry non-cascading FKs, so clear them explicitly.
    cleanup = [
        ("delete from messages where sender_id=$1 or recipient_id=$1",),
        ("delete from notifications where recipient_id=$1",),
        ("update notifications set sender_id=null where sender_id=$1",),
        ("delete from saved_pivots where owner_id=$1",),
        ("update saved_pivots set created_by=null where created_by=$1",),
        ("update audit_trail set actor_id=null where actor_id=$1",),
        ("update attck_mappings set created_by=null where created_by=$1",),
        ("update case_teams set added_by=null where added_by=$1",),
        ("update case_acl set granted_by=null where granted_by=$1",),
        ("delete from password_resets where account_id=$1",),
        ("delete from signatures where created_by=$1",),
    ]
    for (stmt,) in cleanup:
        try:
            await p.execute(stmt, a["id"])
        except Exception:
            pass
    await p.execute("delete from accounts where id=$1", a["id"])
    await audit(p, actor["id"], "account_deleted", "account", a["username"], {"account_id": str(a["id"])})
    return E({"deleted": True, "account_id": str(a["id"]), "username": a["username"]})


@app.get("/api/teams")
async def teams():
    p = await P()
    rows = await p.fetch("""
        select t.*, count(a.id)::int as member_count from teams t
        left join accounts a on a.team_id=t.id
        group by t.id order by case when t.team_type='CPT' then 0 else 1 end, lpad(t.number,3,'0')
    """)
    return E([team_public(r) for r in rows])


@app.post("/api/teams")
async def upsert_team(payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    r = await p.fetchrow("""
        insert into teams(team_type,number,name,description,logo_url,location,phone,email,notes,team_lead_id,deputy_team_lead_id,planner_id,ncoic_id,team_lead_text,deputy_team_lead_text,planner_text,ncoic_text)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
        on conflict(number) do update set team_type=excluded.team_type, name=excluded.name, description=excluded.description, logo_url=excluded.logo_url, location=excluded.location, phone=excluded.phone, email=excluded.email, notes=excluded.notes, team_lead_id=excluded.team_lead_id, deputy_team_lead_id=excluded.deputy_team_lead_id, planner_id=excluded.planner_id, ncoic_id=excluded.ncoic_id, team_lead_text=excluded.team_lead_text, deputy_team_lead_text=excluded.deputy_team_lead_text, planner_text=excluded.planner_text, ncoic_text=excluded.ncoic_text, updated_at=now()
        returning *
    """, payload.get("team_type", "CPT"), payload["number"], payload.get("name") or f"{payload['number']} {'National Cyber Protection Team' if payload.get('team_type') == 'NCPT' else 'Cyber Protection Team'}", payload.get("description", ""), payload.get("logo_url", ""), payload.get("location", ""), payload.get("phone", ""), payload.get("email", ""), payload.get("notes", ""), uuid.UUID(payload["team_lead_id"]) if payload.get("team_lead_id") else None, uuid.UUID(payload["deputy_team_lead_id"]) if payload.get("deputy_team_lead_id") else None, uuid.UUID(payload["planner_id"]) if payload.get("planner_id") else None, uuid.UUID(payload["ncoic_id"]) if payload.get("ncoic_id") else None, payload.get("team_lead_text", ""), payload.get("deputy_team_lead_text", ""), payload.get("planner_text", ""), payload.get("ncoic_text", ""))
    return E(team_public(r))


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
    return E({**team_public(t), "leadership": leadership, "members": [account_public(m) for m in members]})


@app.delete("/api/teams/{team_id}")
async def delete_team(team_id: str, token: str = "", payload: dict = {}):
    p = await P()
    actor = await require_admin_from_token(p, token or (payload or {}).get("token", ""))
    if not actor:
        return E(None, error="admin required")
    t = await p.fetchrow("select * from teams where id=$1 or number=$2", uuid.UUID(team_id) if re.match(r"^[0-9a-f-]{36}$", team_id, re.I) else None, team_id)
    if not t:
        return E(None, error="team not found")
    await p.execute("update accounts set team_id=null where team_id=$1", t["id"])
    await p.execute("update cases set owner_team_id=null where owner_team_id=$1", t["id"])
    await p.execute("delete from teams where id=$1", t["id"])
    await audit(p, actor["id"], "team_deleted", "team", t["number"], {"name": t["name"]})
    return E({"deleted": True, "team_id": str(t["id"])})


@app.get("/api/setup/kibana")
async def kibana_info():
    cfg = await kibana_config(await P())
    return E({"url": cfg["url"], "configured": bool(cfg["url"]), "note": "Set Kibana URL during deployment/admin setup. No private default is shipped."})


@app.get("/api/setup/config")
async def setup_config():
    p = await P()
    return E({"security": await security_config(p), "kibana": await kibana_config(p)})


@app.post("/api/setup/config")
async def save_setup_config(payload: dict):
    p = await P()
    sec = payload.get("security") or {}
    kib = payload.get("kibana") or {}
    sec_cfg = await security_config(p)
    sec_cfg["twofa_required"] = bool(sec.get("twofa_required"))
    await upsert_setting(p, "security", sec_cfg)
    await upsert_setting(p, "kibana", {"url": (kib.get("url") or "").strip()})
    return E({"security": await security_config(p), "kibana": await kibana_config(p)})


@app.post("/api/presence")
async def update_presence(payload: dict):
    token = payload.get("token", "")
    if token:
        await (await P()).execute("update auth_sessions set last_seen_at=now(), current_view=$2 where token=$1 and expires_at>now()", token, payload.get("view", "ops"))
    return E({"ok": True})


@app.get("/api/presence/online")
async def online_users():
    rows = await (await P()).fetch("""
        select distinct on (a.id) a.*, t.name as team_name, t.number as team_number, t.team_type, s.last_seen_at, s.current_view
        from auth_sessions s
        join accounts a on a.id=s.account_id
        left join teams t on t.id=a.team_id
        where s.expires_at>now() and s.last_seen_at>now()-interval '5 minutes'
        order by a.id, s.last_seen_at desc
    """)
    out = []
    for r in rows:
        d = account_public(r)
        d["last_seen_at"] = ser(r["last_seen_at"])
        d["current_view"] = r["current_view"] or "ops"
        out.append(d)
    return E(out)


def chatbot_query_from_question(question: str) -> str:
    q = (question or "").lower()
    terms = []
    if any(x in q for x in ["powershell", "encoded", "iex", "script"]): terms.append("powershell OR encodedcommand OR iex OR process.command_line:powershell*")
    if any(x in q for x in ["rundll32", "dll"]): terms.append("rundll32.exe OR process.executable:*rundll32.exe")
    if any(x in q for x in ["mimikatz", "lsass", "credential", "creds", "dump"]): terms.append("mimikatz OR lsass OR procdump OR comsvcs")
    if any(x in q for x in ["ssh", "password", "login", "auth"]): terms.append("sshd OR failed password OR accepted password OR logon OR event.category:authentication")
    if any(x in q for x in ["aws", "cloud", "cloudtrail", "guardduty", "s3", "iam"]): terms.append("event.dataset:botsv3.cloudtrail OR cloud.provider:aws OR event.provider:*.amazonaws.com OR guardduty")
    if any(x in q for x in ["zeek", "bro", "conn", "ssl", "ja3"]): terms.append("event.module:zeek OR event.dataset:*zeek* OR zeek.uid:*")
    if any(x in q for x in ["dns", "domain", "nxdomain", "query"]): terms.append("event.category:dns OR dns.question.name:* OR dns.response_code:*")
    if any(x in q for x in ["apache", "http", "web", "uri", "url"]): terms.append("event.dataset:botsv3.apache OR event.dataset:botsv3.web OR http.request.method:*")
    if any(x in q for x in ["proxy", "wpad", "connect"]): terms.append("event.dataset:botsv3.proxy OR http.request.method:CONNECT OR wpad")
    if any(x in q for x in ["suricata", "ids", "alert", "signature"]): terms.append("event.module:suricata OR event.dataset:botsv3.suricata OR rule.name:*")
    if any(x in q for x in ["sql", "mysql", "database"]): terms.append("mysql OR SELECT OR CONNECT")
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question or "")
    procs = re.findall(r"\b[a-zA-Z0-9_\-]+\.exe\b", question or "")
    terms.extend(ips + procs)
    return " OR ".join(f"({t})" for t in terms[:8]) or "powershell OR rundll32.exe OR mimikatz OR sshd OR event.dataset:botsv3.cloudtrail OR mysql"


async def chatbot_elastic_context(question: str) -> dict:
    query = chatbot_query_from_question(question)
    try:
        res = await es_request("GET", "/botsv3-ecs-v2,botsv3-raw,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*,spotter-zeek-*/_search", {
            "size": 5,
            "query": {"query_string": {"query": query, "default_field": "*"}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        }, timeout=12)
        hits = res.get("hits", {})
        total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        samples = []
        for h in hits.get("hits", []):
            src = h.get("_source", {})
            text = json.dumps(src, default=str)[:1800]
            samples.append({"index": h.get("_index"), "id": h.get("_id"), "score": h.get("_score"), "sample": text})
        return {"query": query, "total": total, "samples": samples}
    except Exception as exc:
        return {"query": query, "total": 0, "samples": [], "error": str(exc)[:500]}


@app.get("/api/messages")
async def list_messages(token: str = "", with_user: str = "", limit: int = 50):
    """Direct messages between accounts."""
    p = await P()
    actor = await get_actor(p, token)
    sql = "select m.*, a1.display_name as sender_name, a2.display_name as recipient_name from messages m join accounts a1 on a1.id=m.sender_id join accounts a2 on a2.id=m.recipient_id where (m.sender_id=$1 and m.recipient_id=$2::uuid) or (m.sender_id=$2::uuid and m.recipient_id=$1) order by m.created_at asc limit $3"
    rows = await p.fetch(sql, actor["id"], with_user, limit)
    return E([{"id":str(r["id"]),"sender_name":r["sender_name"],"recipient_name":r["recipient_name"],"body":r["body"],"read_at":ser(r["read_at"]),"created_at":ser(r["created_at"])} for r in rows])


@app.post("/api/messages")
async def send_message(payload: dict):
    """Send direct message to another account."""
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    if not actor: return E(None, error="must be authenticated")
    recipient_id = payload.get("recipient_id")
    if not recipient_id: return E(None, error="recipient_id required")
    r = await p.fetchrow(
        "insert into messages(sender_id,recipient_id,body) values($1,$2,$3) returning *",
        actor["id"], uuid.UUID(recipient_id), payload.get("body", "")
    )
    # Create notification for recipient
    try:
        await p.execute(
            "insert into notifications(recipient_id,sender_id,n_type,body) values($1,$2,'message',$3)",
            uuid.UUID(recipient_id), actor["id"], (actor["display_name"]+": "+payload.get("body","")[:120])
        )
    except: pass
    return E(rd(r) if r else None)


@app.post("/api/messages/{msg_id}/read")
async def mark_message_read(msg_id: str, payload: dict):
    await (await P()).execute("update messages set read_at=now() where id=$1", uuid.UUID(msg_id))
    return E({"read": True})

# Migration for messages table is needed:
@app.on_event("startup")
async def create_messages_table():
    try:
        p = await P()
        await p.execute("""
            create table if not exists messages(
                id uuid primary key default gen_random_uuid(),
                sender_id uuid references accounts(id),
                recipient_id uuid references accounts(id),
                body text,
                read_at timestamptz,
                created_at timestamptz default now()
            )
        """)
        await p.execute("""
            create table if not exists chat_history(
                id uuid primary key default gen_random_uuid(),
                token text not null,
                role text not null default 'analyst',
                seq int not null default 0,
                message text not null,
                answer text not null,
                created_at timestamptz default now()
            )
        """)
        # Cleanup old chat history on startup (keep last 20 per token+role)
        await p.execute("""
            delete from chat_history where id in (
                select id from (
                    select id, row_number() over (partition by token, role order by seq desc) as rn
                    from chat_history
                ) sub where rn > 20
            )
        """)
        # Restore persisted hunt configuration (index pattern, interval) across API restarts.
        await load_hunt_setting(p)
    except: pass


@app.post("/api/chat")
async def chat(payload: dict):
    role = payload.get("role", "analyst")
    question = payload.get("message", "")[:2000]  # type: str
    p = await P()
    if payload.get("token"):
        await p.execute("update auth_sessions set last_seen_at=now(), current_view=$2 where token=$1 and expires_at>now()", payload.get("token"), f"{role}_chat")
    # Conversation history: last 6 turns for this session+role
    token = payload.get("token", "")
    history = []
    if token:
        rows = await p.fetch("select role,message,answer from chat_history where token=$1 and role=$2 order by seq desc limit 6", token, role)
        for r in reversed(rows):
            history.append({"role": "user", "content": r["message"]})
            history.append({"role": "assistant", "content": r["answer"]})
    seq = (await p.fetchrow("select coalesce(max(seq),0)+1 as next from chat_history where token=$1 and role=$2", token, role))["next"] if token else 0

    # Live context snapshots
    events = [dict(r) for r in await p.fetch("select event_id,title,severity,status,explanation from events order by updated_at desc limit 8")]
    cases = [dict(r) for r in await p.fetch("select case_id,name,status,final_output,narrative_summary from cases order by updated_at desc limit 5")]
    elastic = await chatbot_elastic_context(question) if question else {"query": "", "total": 0, "samples": []}

    commander_system = (
        "You are a senior SOC Commander briefing assistant. You give crisp, executive-level answers. "
        "NEVER dump raw Elastic queries, match counts, or query strings. "
        "Answer from the analyst perspective. Do not repeat event details. "
        "Ask one sharp follow-up when helpful. Be direct, not interrogative. "
        "If asked a follow-up about the same case/session, use the previous turns as context. "
        "When the user says 'don't tell me about X' or similar, acknowledge it and pivot. "
        "Structure: 1-2 sentence direct answer first. Then bullet points if needed. "
        "Tone: confident, professional, no filler. "
        "Your knowledge comes ONLY from the context provided (open cases, active events, and Elastic snapshots). "
        "If a question asks about something outside your available data — say 'I don't have data on that in the current search scope' rather than guessing."
    )
    analyst_system = (
        "You are a senior threat-hunting analyst assistant. You help triage, pivot, and build cases. "
        "Reference specific event IDs, hosts, techniques. Cite Elastic query results naturally without dumping syntax. "
        "Answer directly, give concrete next steps. Do not be interrogative. "
        "Structure: direct answer, then recommended action. Keep it concise. "
        "Your knowledge comes ONLY from the context provided (active events, open cases, and Elastic search results). "
        "Critical: if elastic_snapshot.total is greater than zero, matching live Elastic logs DO exist; summarize the matching samples and never claim there is no data for that pattern. "
        "If elastic_snapshot.total is zero and a question asks about something outside your available data — explicitly state 'I don't have logs covering that in the current data scope' or 'I'm not querying live Elastic for that pattern right now' rather than inventing findings. "
        "If the user asks you to search for something but you don't want to or shouldn't — tell them clearly: 'That's outside my current query scope' or 'I'm not set up to search for that pattern'."
    )

    system_prompt = commander_system if role == "commander" else analyst_system
    context_block = json.dumps({"top_events": events, "open_cases": cases, "elastic_snapshot": elastic}, default=str)[:4000]

    messages = [{"role": "system", "content": system_prompt}] + history + [{"role": "user", "content": f"{question}\n\nContext:\n{context_block}"}]

    if settings.openrouter_api_key:
        headers = {"Authorization": f"Bearer {settings.openrouter_api_key}", "Content-Type": "application/json", "HTTP-Referer": "http://127.0.0.1:8097", "X-Title": "Spotter-Shooter MVP"}
        chat_payload = {"model": settings.openrouter_model, "messages": messages, "temperature": 0.3, "max_tokens": 600}
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=chat_payload)
            r.raise_for_status()
            answer = r.json()["choices"][0]["message"]["content"].strip()
        model_used = settings.openrouter_model.split("/")[-1]
        # Guardrail: if live Elastic returned matches, never let the model claim there is no data.
        if elastic.get("total", 0) and any(phrase in answer.lower() for phrase in ["don't have logs", "no logs", "no data", "current data scope"]):
            answer = f"Live Elastic has {elastic.get('total')} matching events for this query. Review the returned samples and pivot on the ECS fields shown in the Elastic snapshot."
        # Store in history
        if token:
            await p.execute("insert into chat_history(token,role,seq,message,answer) values($1,$2,$3,$4,$5)", token, role, seq, question[:2000], answer[:3000])
        return E({"answer": answer, "model": model_used, "role": role, "elastic": elastic})

    # Deterministic fallback when no OpenRouter
    fallback_cmd = "Review open cases for unresolved items. Focus on affected assets, decisions needed, and resource allocation." if role == "commander" else "Review highest-severity open alerts, confirm raw evidence, and update the case timeline."
    return E({"answer": fallback_cmd, "model": "deterministic", "role": role, "elastic": elastic})



RESET_TABLES = [
    "signatures", "agent_state", "notifications", "messages", "chat_history", "saved_pivots",
    "audit_trail", "attck_mappings", "case_teams", "case_acl", "case_members", "case_indicators",
    "case_timeline", "case_events", "cases", "events", "asom_lines", "assets", "documents",
    "hunt_sessions", "custom_agents", "password_resets", "login_challenges", "auth_sessions",
    "accounts", "teams", "enrichment_configs", "app_settings",
]


@app.post("/api/admin/reset")
async def admin_reset(payload: dict):
    """Factory reset: wipe all operational data and accounts so the setup process starts over."""
    global migrated
    p = await P()
    actor = await require_admin_from_token(p, (payload or {}).get("token", ""))
    if not actor:
        return E(None, error="admin required")
    if (payload or {}).get("confirm") != "REDEPLOY":
        return E(None, error="confirmation phrase required: send confirm='REDEPLOY'")
    wiped = []
    for table in RESET_TABLES:
        try:
            await p.execute(f"truncate table {table} cascade")
            wiped.append(table)
        except Exception:
            pass
    # Re-seed defaults (app settings, CPT/NCPT teams, enrichment configs).
    migrated = False
    await migrate_db(p)
    migrated = True
    _agent_cycle_params.update({"interval_seconds": 120, "max_concurrent": 4, "enabled": True, "index_pattern": HUNT_INDEXES})
    # The actor's account was just wiped; record the reset with the username in details.
    await audit(p, None, "platform_reset", "system", "all", {"by_username": actor["username"], "wiped_tables": wiped})
    return E({"reset": True, "wiped_tables": wiped, "next": "/deployment.html"})


@app.get("/api/setup/bootstrap")
async def setup_bootstrap():
    """Setup wizard helper: does an admin account exist yet?"""
    p = await P()
    admins = await p.fetchval("select count(*) from accounts where privilege_level='admin'")
    return E({"admin_exists": int(admins or 0) > 0})


@app.post("/api/setup/admin")
async def setup_create_admin(payload: dict):
    """Create the FIRST admin account during deployment. Only allowed while no admin exists."""
    p = await P()
    admins = await p.fetchval("select count(*) from accounts where privilege_level='admin'")
    if int(admins or 0) > 0 and not await require_admin_from_token(p, (payload or {}).get("token", "")):
        return E(None, error="an admin account already exists; log in instead")
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if not username:
        return E(None, error="username required")
    if len(password) < 6:
        return E(None, error="password must be at least 6 characters")
    first_name, last_name, display_name = normalize_person_name(payload)
    r = await p.fetchrow("""
        insert into accounts(username,display_name,first_name,last_name,privilege_level,service_branch,rank,work_role,skill_level,email,phone,password_hash)
        values($1,$2,$3,$4,'admin',$5,$6,$7,$8,$9,$10,$11)
        on conflict(username) do update set privilege_level='admin', display_name=excluded.display_name, first_name=excluded.first_name, last_name=excluded.last_name, service_branch=excluded.service_branch, rank=excluded.rank, work_role=excluded.work_role, skill_level=excluded.skill_level, email=excluded.email, phone=excluded.phone, password_hash=excluded.password_hash, updated_at=now()
        returning *
    """, username, display_name, first_name, last_name, payload.get("service_branch", ""), payload.get("rank", ""), payload.get("work_role", "Team Lead"), payload.get("skill_level", "Senior"), payload.get("email", ""), payload.get("phone", ""), hash_password(password))
    token = secrets.token_urlsafe(32)
    await p.execute("insert into auth_sessions(token,account_id,expires_at,last_seen_at,current_view) values($1,$2,now()+interval '12 hours',now(),'setup')", token, r["id"])
    await audit(p, r["id"], "bootstrap_admin_created", "account", r["username"])
    return E({"token": token, "account": account_public(r)})


@app.get("/api/admin/overview")
async def admin_overview(token: str = ""):
    p = await P()
    actor = await require_admin_from_token(p, token)
    if not actor:
        return E(None, error="admin required")
    counts = {}
    for key, sql in {
        "accounts": "select count(*) from accounts",
        "teams": "select count(*) from teams",
        "events": "select count(*) from events",
        "cases": "select count(*) from cases",
        "sessions": "select count(*) from hunt_sessions",
        "custom_agents": "select count(*) from custom_agents where archived_at is null",
        "online": "select count(distinct account_id) from auth_sessions where expires_at>now() and last_seen_at>now()-interval '5 minutes'",
    }.items():
        counts[key] = int(await p.fetchval(sql) or 0)
    token_estimate = int(await p.fetchval("select coalesce(sum(length(explanation)+length(raw_log_sample)+length(recommended_next_question)),0)/4 from events") or 0)
    recent = [dict(r) for r in await p.fetch("select name,status,created_at,updated_at from hunt_sessions order by updated_at desc limit 8")]
    return E({"counts": counts, "token_usage_estimate": token_estimate, "recent_tasks": recent, "security": await security_config(p), "kibana": await kibana_config(p)})

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
    hunt_state = {r["agent"]: r for r in await p.fetch("select * from agent_state")}
    sig_last_run = await p.fetchval("select max(last_run_at) from signatures where enabled=true")
    custom = []
    for r in custom_rows:
        d = rd(r)
        d["status"] = "archived" if d.get("archived_at") else ("enabled" if d.get("enabled") else "disabled")
        d["event_count"] = event_counts.get(d.get("role_string"), 0)
        st = hunt_state.get("custom:" + (d.get("role_string") or ""))
        d["last_hunt_at"] = ser(st["last_run_at"]) if st else None
        d["last_match_total"] = int(st["last_total"]) if st else None
        custom.append(d)
    built_in = []
    for n, r, t, tier, en in BUILTIN:
        st = hunt_state.get(r)
        built_in.append({
            "name": n, "role_string": r, "telemetry_source": t, "tier": tier, "enabled": en,
            "status": "enabled" if en else "disabled", "event_count": event_counts.get(r, 0),
            "last_hunt_at": ser(sig_last_run) if r == "signature_agent" else (ser(st["last_run_at"]) if st else None),
            "last_match_total": int(st["last_total"]) if st else None,
        })
    last_cycle_at = await p.fetchval("select max(last_run_at) from agent_state")
    return E({
        "built_in": built_in,
        "custom": custom,
        "cycle": {"enabled": _agent_cycle_params["enabled"], "interval_seconds": _agent_cycle_params["interval_seconds"], "last_cycle_at": ser(last_cycle_at)},
    })


@app.get("/api/agents/custom")
async def list_custom_agents(include_archived: bool = False):
    p = await P()
    rows = await p.fetch("select * from custom_agents {} order by created_at desc".format("" if include_archived else "where archived_at is null"))
    event_counts = {r["agent"]: r["count"] for r in await p.fetch("select agent, count(*)::int as count from events group by agent")}
    out = []
    for r in rows:
        d = rd(r)
        d["status"] = "archived" if d.get("archived_at") else ("enabled" if d.get("enabled") else "disabled")
        d["event_count"] = event_counts.get(d.get("role_string"), 0)
        out.append(d)
    return E(out)


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
        hits = await es_request("GET", "/botsv3-ecs-v2,botsv3-raw,apt29-*,apt3-*,lsass-*/_search", {"size": 1, "query": {"query_string": {"query": query, "default_field": "*"}}})
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
            res = await es_request("GET", "/botsv3-ecs-v2,botsv3-raw,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*/_search?ignore_unavailable=true&allow_no_indices=true", {
                "size": 1,
                "query": {"query_string": {"query": item["query"], "default_field": "*"}},
            })
            total = res.get("hits", {}).get("total", {})
            count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
            hits = res.get("hits", {}).get("hits", [])
            if hits:
                raw = hits[0].get("_source", {})
        except Exception:
            # No reachable telemetry for this query: do not create an evidence-free alert.
            continue
        if count == 0:
            continue
        evidence = {"title": item["title"], "query": item["query"], "match_count": count, "raw_sample": raw, "fallback_explanation": item["fallback_explanation"]}
        ai = await openrouter_agent_summary(item["agent"], evidence, item["severity"])
        enrichment = item["enrichment"] + [{"label": "Matching Events", "value": str(count), "color": "highlight"}, {"label": "Model", "value": ai.get("model_used", "unknown"), "color": "highlight"}]
        tags = [{"text": "Live Backend", "type": "intel"}, {"text": "OpenRouter Agent" if ai.get("model_used") not in {"not_configured", "error"} else "Deterministic Agent", "type": "context"}]
        agent_sum = json.dumps({k: ai.get(k, "") for k in ("who","what","when","where","why","how") if ai.get(k)})
        await p.execute(
            "insert into events(event_id,session_id,agent,severity,title,snippet,explanation,enrichment,tags,recommended_next_question,raw_log_sample,confidence,metadata,agent_summary) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) on conflict(event_id) do update set session_id=excluded.session_id,status='new',updated_at=now(),title=excluded.title,explanation=excluded.explanation,recommended_next_question=excluded.recommended_next_question,raw_log_sample=excluded.raw_log_sample,enrichment=excluded.enrichment,tags=excluded.tags,confidence=excluded.confidence,metadata=excluded.metadata,agent_summary=excluded.agent_summary",
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
            agent_sum,
        )
    await p.execute(
        "insert into asom_lines(session_id,line_no,title,status) values($1,1,'Confirm suspicious PowerShell execution scope','active'),($1,2,'Validate credential-access indicators','pending'),($1,3,'Assess cloud-control-plane exposure','pending') on conflict do nothing",
        uuid.UUID(sid),
    )


@app.post("/api/setup/launch")
async def launch(payload: dict = {}):
    p = await P()
    cfg = payload or {}
    if "security" in cfg or "kibana" in cfg:
        sec = cfg.get("security") or {}
        kib = cfg.get("kibana") or {}
        sec_cfg = await security_config(p)
        if "twofa_required" in sec:
            sec_cfg["twofa_required"] = bool(sec.get("twofa_required"))
        await upsert_setting(p, "security", sec_cfg)
        await upsert_setting(p, "kibana", {"url": (kib.get("url") or "").strip()})
    # Hunt scope: explicit index selection from setup wins; then a manual pattern; else all non-system indices.
    tel = cfg.get("telemetry") or {}
    hunt_list = cfg.get("hunt_indexes") or tel.get("hunt_indexes") or []
    pattern = ",".join(x for x in hunt_list if x)[:2000] if hunt_list else (tel.get("index_pattern") or "").strip()
    _agent_cycle_params["index_pattern"] = pattern or HUNT_INDEXES
    await save_hunt_setting(p)
    r = await p.fetchrow("insert into hunt_sessions(status,config) values('active',$1) returning *", json.dumps(cfg))
    await seed(str(r["id"]), payload)
    # Record baseline match counts so the continuous cycle alerts only on NEW telemetry from here on.
    try:
        await run_agent_cycle(p, str(r["id"]), baseline_only=True)
    except Exception:
        pass
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

# ═══════════════════════════════════════════════════════════
# FULL TEXT SEARCH
# ═══════════════════════════════════════════════════════════

@app.get("/api/directory")
async def api_directory(token: str = ""):
    """Public directory - all logged-in users can search for people to message. Admin-only fields are hidden."""
    actor = await get_actor(await P(), token)
    if not token:
        return E([])  # Anonymous users see no directory
    rows = await (await P()).fetch(
        "select a.id,a.display_name,a.username,a.rank,a.service_branch,a.work_role,a.skill_level,a.team,a.bio,a.team_id,a.email,a.phone,t.name as team_name,t.number as team_number,t.team_type from accounts a left join teams t on t.id=a.team_id order by a.display_name"
    )
    result = []
    for r in rows:
        entry = {
            "id": str(r["id"]),
            "name": r["display_name"] or r["username"] or "",
            "rank": r["rank"] or "",
            "branch": r["service_branch"] or "",
            "role": r["work_role"] or "",
            "skill": r["skill_level"] or "",
            "team": r["team_name"] or r["team"] or "",
            "team_display": team_display(r) if r.get("team_number") or r.get("team_type") else (r["team"] or ""),
            "bio": r["bio"] or "",
        }
        result.append(entry)
    return E(result)

@app.get("/api/search")
async def full_text_search(q: str = "", limit: int = 30, token: str = ""):
    """Search across cases, timeline, indicators, accounts, teams."""
    if not q or len(q.strip()) < 2:
        return E({"results": [], "query": q, "total": 0})
    q = q.strip()
    p = await P()
    actor = await get_actor(p, token)
    is_admin = actor.get("privilege_level") == "admin"

    results = []
    like_pattern = f"%{q}%"
    
    def add_result(rtype, eid, score, entity, fields):
        results.append({"type": rtype, "id": eid, "score": score, "entity": entity, **fields})

    # Cases - name, bluf, technical_summary, way_ahead, five_ws, how
    case_rows = await p.fetch("""
        SELECT id, case_id, name, bluf, technical_summary, way_ahead, five_ws, how, status
        FROM cases
        WHERE name ILIKE $1 OR bluf ILIKE $1 OR technical_summary ILIKE $1 OR way_ahead ILIKE $1
           OR five_ws::text ILIKE $1 OR how ILIKE $1
        ORDER BY updated_at DESC LIMIT $2
    """, like_pattern, limit)
    for r in case_rows:
        score = 0
        for col in ("name", "bluf", "technical_summary", "way_ahead"):
            v = r[col] or ""
            if q.lower() in v.lower(): score += 3
        for col in ("five_ws", "how"):
            v = r[col] or ""
            if q.lower() in v.lower(): score += 1
        five = _jsonish(r["five_ws"]) or {}
        add_result("case", r["case_id"], score, {
            "name": r["name"], "status": r["status"],
            "bluf": (r["bluf"] or "")[:200],
            "five_ws": {"who": five.get("who",""), "what": five.get("what",""), "when": five.get("when",""),
                         "where": five.get("where",""), "why": five.get("why","")},
            "how": r.get("how","") or "",
            "technical_summary": (r["technical_summary"] or "")[:200],
        })

    # Timeline entries
    tl_rows = await p.fetch("""
        SELECT ct.id, ct.case_id, ct.event_time, ct.entry_type, ct.title, ct.body, ct.actor_name, c.case_id as case_ref
        FROM case_timeline ct
        LEFT JOIN cases c ON c.id = ct.case_id
        WHERE ct.title ILIKE $1 OR ct.body ILIKE $1
        ORDER BY ct.created_at DESC LIMIT $2
    """, like_pattern, limit)
    for r in tl_rows:
        score = 3 if q.lower() in (r["title"] or "").lower() else 1
        add_result("timeline", str(r["id"]), score, {
            "case_id": r["case_ref"], "entry_type": r["entry_type"],
            "title": r["title"], "body": (r["body"] or "")[:300],
            "actor": r.get("actor_name",""), "event_time": ser(r["event_time"]),
        })

    # Indicators
    ind_rows = await p.fetch("""
        SELECT ci.id, ci.case_id, ci.indicator_type, ci.value, ci.description, c.case_id as case_ref
        FROM case_indicators ci
        LEFT JOIN cases c ON c.id = ci.case_id
        WHERE ci.value ILIKE $1 OR ci.description ILIKE $1 OR ci.indicator_type ILIKE $1
        ORDER BY ci.created_at DESC LIMIT $2
    """, like_pattern, limit)
    for r in ind_rows:
        score = 5 if q.lower() in (r["value"] or "").lower() else 1
        add_result("indicator", str(r["id"]), score, {
            "case_id": r["case_ref"], "indicator_type": r["indicator_type"],
            "value": r["value"], "description": (r["description"] or "")[:200],
        })

    # Accounts (admin only)
    if is_admin:
        acc_rows = await p.fetch("""
            SELECT a.id, a.username, a.display_name, a.rank, a.service_branch, a.work_role,
                   a.skill_level, a.bio, a.certs, a.degrees,
                   t.name as team_name, t.team_type, t.number as team_number
            FROM accounts a
            LEFT JOIN teams t ON t.id = a.team_id
            WHERE a.username ILIKE $1 OR a.display_name ILIKE $1 OR a.rank ILIKE $1
               OR a.work_role ILIKE $1 OR a.bio ILIKE $1 OR a.certs ILIKE $1
               OR a.email ILIKE $1 OR a.phone ILIKE $1
            ORDER BY a.display_name LIMIT $2
        """, like_pattern, limit)
        for r in acc_rows:
            score = 3
            for col in ("username", "display_name", "rank", "work_role", "bio", "certs"):
                if q.lower() in (r[col] or "").lower(): score += 1
            td = team_display(r) or ""
            add_result("account", str(r["id"]), score, {
                "username": r["username"], "display_name": r["display_name"],
                "rank": r["rank"], "work_role": r["work_role"],
                "skill_level": r["skill_level"], "branch": r["service_branch"],
                "email": r.get("email",""), "phone": r.get("phone",""),
                "team": {"name": r.get("team_name",""), "type": r.get("team_type",""),
                         "number": r.get("team_number",""), "display": td},
                "bio": (r.get("bio","") or "")[:200],
                "certs": r.get("certs","") or "",
            })

        # Teams (admin only)
        team_rows = await p.fetch("""
            SELECT id, team_type, number, name, description, logo_url, location, phone, email, notes
            FROM teams
            WHERE name ILIKE $1 OR description ILIKE $1 OR location ILIKE $1
               OR notes ILIKE $1 OR number::text ILIKE $1 OR email ILIKE $1
            ORDER BY number LIMIT $2
        """, like_pattern, limit)
        for r in team_rows:
            score = 5 if (r["number"] and str(r["number"]) == q.strip()) else (3 if q.lower() in (r["name"] or "").lower() else 1)
            td = team_display(r)
            add_result("team", str(r["id"]), score, {
                "type": r["team_type"], "number": r.get("number",""),
                "name": td, "raw_name": r["name"],
                "location": r.get("location","") or "",
                "phone": r.get("phone","") or "",
                "email": r.get("email","") or "",
                "description": (r.get("description","") or "")[:200],
                "notes": (r.get("notes","") or "")[:300],
            })

    # Also query Elastic if the query looks like an indicator
    elastic_hits = []
    try:
        es_url = _safe_es_url(settings.elasticsearch_url)
        user = urlparse(es_url).username
        pw = urlparse(es_url).password
        res = await es_request("POST", "/_search?size=5&ignore_unavailable=true", payload={
            "query": {
                "multi_match": {
                    "query": q,
                    "fields": ["message", "url", "host*", "user*", "process*"],
                    "fuzziness": "AUTO"
                }
            }
        }, base_url=es_url, username=user, password=pw)
        if res and res.get("hits"):
            for h in res["hits"].get("hits", [])[:5]:
                src = h.get("_source", {})
                elastic_hits.append({
                    "index": h.get("_index"),
                    "id": h.get("_id"),
                    "score": h.get("_score", 0),
                    "sample": json.dumps(src, default=str)[:400],
                })
    except Exception:
        pass

    # Sort by score desc, limit
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    results = results[:limit]

    # Count by type
    type_counts = {}
    for r in results:
        type_counts[r["type"]] = type_counts.get(r["type"], 0) + 1

    return E({
        "query": q,
        "results": results,
        "total": len(results),
        "type_counts": type_counts,
        "elastic_matches": elastic_hits,
    })


# ═══════════════════════════════════════════════════════════
# PASSWORD RESET
# ═══════════════════════════════════════════════════════════
@app.post("/api/auth/password-reset-request")
async def password_reset_request(payload: dict):
    username = payload.get("username", "").strip()
    method = payload.get("method", "email")
    if not username:
        return E(None, error="username, email, or phone required")
    a = await (await P()).fetchrow(
        "select * from accounts where username=$1 or email=$1 or phone=$1", username
    )
    if not a:
        return E({"delivered": True}, note="If the account exists, a reset code will be sent.")
    code = f"{random.randint(100000, 999999)}"
    dest = a["phone"] if method == "sms" else (a["email"] or a["contact"] or "demo")
    r = await (await P()).fetchrow(
        "insert into password_resets(account_id,code_hash,delivered_to,method,expires_at) values($1,$2,$3,$4,now()+interval '15 minutes') returning id",
        a["id"], hash_code(code), dest, method
    )
    delivery = await send_otp(method, dest, code)
    return E({"challenge_id": str(r["id"]), "method": method, "destination": dest, **delivery})

@app.post("/api/auth/password-reset-verify")
async def password_reset_verify(payload: dict):
    code = payload.get("code", "").strip()
    new_password = payload.get("new_password", "")
    if len(new_password) < 6:
        return E(None, error="password must be at least 6 characters")
    p = await P()
    ch = await p.fetchrow(
        "select * from password_resets where id=$1 and used_at is null and expires_at>now()",
        uuid.UUID(payload.get("challenge_id", ""))
    )
    if not ch or not hmac.compare_digest(ch["code_hash"], hash_code(code)):
        return E(None, error="invalid or expired code")
    await p.execute("update password_resets set used_at=now() where id=$1", ch["id"])
    pw_hash = hash_password(new_password)
    await p.execute("update accounts set password_hash=$1 where id=$2", pw_hash, ch["account_id"])
    # Invalidate existing sessions
    await p.execute("delete from auth_sessions where account_id=$1", ch["account_id"])
    return {"reset": True}

# ═══════════════════════════════════════════════════════════
# AUDIT TRAIL
# ═══════════════════════════════════════════════════════════
@app.post("/api/audit")
async def audit_log(payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    await p.execute(
        "insert into audit_trail(actor_id,action,target_type,target_id,details) values($1,$2,$3,$4,$5)",
        actor["id"], payload.get("action", ""), payload.get("target_type", ""),
        payload.get("target_id", ""), json.dumps(payload.get("details", {}))
    )
    return E({"logged": True})

@app.get("/api/audit")
async def audit_list(token: str = "", target_type: str = "", limit: int = 100):
    p = await P()
    actor = await get_actor(p, token)
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    sql = "select at.*, a.display_name as actor_name from audit_trail at left join accounts a on a.id=at.actor_id order by created_at desc limit $1"
    params = [limit]
    if target_type:
        sql = "select at.*, a.display_name as actor_name from audit_trail at left join accounts a on a.id=at.actor_id where at.target_type=$2 order by created_at desc limit $1"
        params = [limit, target_type]
    rows = await p.fetch(sql, *params)
    return E([{"id":str(r["id"]),"actor_name":r["actor_name"],"action":r["action"],"target_type":r["target_type"],"target_id":r["target_id"],"details":r["details"],"created_at":ser(r["created_at"])} for r in rows])

# ═══════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════
@app.post("/api/notifications")
async def create_notification(payload: dict):
    p = await P()
    r = await p.fetchrow(
        "insert into notifications(recipient_id,sender_id,n_type,body,case_id,event_id) values($1,$2,$3,$4,$5,$6) returning *",
        uuid.UUID(payload["recipient_id"]) if payload.get("recipient_id") else None,
        uuid.UUID(payload["sender_id"]) if payload.get("sender_id") else None,
        payload.get("n_type", "info"), payload.get("body", ""),
        uuid.UUID(payload["case_id"]) if payload.get("case_id") and payload["case_id"] != "null" else None,
        payload.get("event_id")
    )
    return E(rd(r) if r else None)

@app.get("/api/notifications")
async def list_notifications(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    rows = await p.fetch(
        "select n.*, a.display_name as sender_name from notifications n left join accounts a on a.id=n.sender_id where n.recipient_id=$1 and n.read_at is null order by n.created_at desc limit 50",
        actor["id"]
    )
    return E([{"id":str(r["id"]),"sender_name":r["sender_name"],"n_type":r["n_type"],"body":r["body"],"case_id":str(r["case_id"]) if r["case_id"] else None,"event_id":r["event_id"],"created_at":ser(r["created_at"])} for r in rows])

@app.post("/api/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str, payload: dict = {}):
    await (await P()).execute("update notifications set read_at=now() where id=$1", uuid.UUID(notif_id))
    return E({"read": True})

@app.get("/api/notifications/unread-count")
async def unread_count(token: str = ""):
    actor = await get_actor(await P(), token)
    count = await (await P()).fetchval("select count(*) from notifications where recipient_id=$1 and read_at is null", actor["id"])
    return E({"count": count or 0})

# ═══════════════════════════════════════════════════════════
# ANALYST SIGNATURES — simple ECS field:value rules that feed the Signature Match Agent
# ═══════════════════════════════════════════════════════════
@app.get("/api/signatures")
async def list_signatures(token: str = ""):
    p = await P()
    actor = await session_actor(p, token)
    if not actor:
        return E(None, error="login required")
    rows = await p.fetch("select s.*, a.display_name as creator_display from signatures s left join accounts a on a.id=s.created_by order by s.created_at desc")
    out = []
    for r in rows:
        d = rd(r)
        d["mine"] = str(r["created_by"]) == str(actor["id"]) if r["created_by"] else False
        out.append(d)
    return E(out)


@app.post("/api/signatures")
async def create_signature(payload: dict):
    p = await P()
    actor = await session_actor(p, payload.get("token", ""))
    if not actor:
        return E(None, error="login required")
    value = (payload.get("value") or "").strip()
    if not value:
        return E(None, error="signature value required (IP, domain, username, hash, or any ECS value)")
    name = (payload.get("name") or value).strip()[:120]
    field = (payload.get("field") or "").strip()[:120]
    severity = payload.get("severity") if payload.get("severity") in ("critical", "high", "medium", "low") else "medium"
    r = await p.fetchrow(
        "insert into signatures(name,description,field,value,severity,enabled,created_by,created_by_name) values($1,$2,$3,$4,$5,true,$6,$7) returning *",
        name, (payload.get("description") or "")[:1000], field, value, severity, actor["id"], actor["display_name"],
    )
    # Immediate feedback: how many events match right now. The cycle will alert on this baseline pop too.
    matches_now = None
    try:
        matches_now, _ = await es_agent_search(signature_query(field, value))
    except Exception:
        pass
    await audit(p, actor["id"], "signature_created", "signature", name, {"field": field, "value": value, "severity": severity})
    return E({**rd(r), "matches_now": matches_now, "mine": True})


@app.post("/api/signatures/{sig_id}/enable")
async def enable_signature(sig_id: str, payload: dict = {}):
    return await _toggle_signature(sig_id, payload, True)


@app.post("/api/signatures/{sig_id}/disable")
async def disable_signature(sig_id: str, payload: dict = {}):
    return await _toggle_signature(sig_id, payload, False)


async def _toggle_signature(sig_id: str, payload: dict, enabled: bool):
    p = await P()
    actor = await session_actor(p, (payload or {}).get("token", ""))
    if not actor:
        return E(None, error="login required")
    s = await p.fetchrow("select * from signatures where id=$1", uuid.UUID(sig_id))
    if not s:
        return E(None, error="signature not found")
    if actor["privilege_level"] != "admin" and str(s["created_by"]) != str(actor["id"]):
        return E(None, error="only the signature creator or an admin can change it")
    r = await p.fetchrow("update signatures set enabled=$2, updated_at=now() where id=$1 returning *", s["id"], enabled)
    return E(rd(r))


@app.delete("/api/signatures/{sig_id}")
async def delete_signature(sig_id: str, token: str = "", payload: dict = {}):
    p = await P()
    actor = await session_actor(p, token or (payload or {}).get("token", ""))
    if not actor:
        return E(None, error="login required")
    s = await p.fetchrow("select * from signatures where id=$1", uuid.UUID(sig_id))
    if not s:
        return E(None, error="signature not found")
    if actor["privilege_level"] != "admin" and str(s["created_by"]) != str(actor["id"]):
        return E(None, error="only the signature creator or an admin can delete it")
    await p.execute("delete from signatures where id=$1", s["id"])
    await audit(p, actor["id"], "signature_deleted", "signature", s["name"], {"field": s["field"], "value": s["value"]})
    return E({"deleted": True})


@app.post("/api/signatures/{sig_id}/test")
async def test_signature(sig_id: str, payload: dict = {}):
    p = await P()
    s = await p.fetchrow("select * from signatures where id=$1", uuid.UUID(sig_id))
    if not s:
        return E(None, error="signature not found")
    query = signature_query(s["field"], s["value"])
    try:
        total, sample = await es_agent_search(query)
        return E({"query": query, "matching_events": total, "sample": sample})
    except Exception as exc:
        return E({"query": query, "matching_events": 0}, error=str(exc)[:300])


# ═══════════════════════════════════════════════════════════
# SAVED PIVOTS (KQL/DSL → Kibana)
# ═══════════════════════════════════════════════════════════
@app.get("/api/pivots")
async def list_pivots(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    rows = await p.fetch(
        "select * from saved_pivots where owner_id=$1 or shared=true order by created_at desc",
        actor["id"]
    )
    return E([rd(r) for r in rows])

@app.post("/api/pivots")
async def create_pivot(payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token", ""))
    r = await p.fetchrow(
        "insert into saved_pivots(name,description,query,dsl,index_pattern,time_range,created_by,owner_id,shared) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *",
        payload.get("name",""), payload.get("description",""), payload.get("query",""),
        json.dumps(payload.get("dsl",{})), payload.get("index_pattern",""),
        payload.get("time_range",""), actor["id"], actor["id"], payload.get("shared", False)
    )
    return E(rd(r) if r else None)

@app.delete("/api/pivots/{pivot_id}")
async def delete_pivot(pivot_id: str, payload: dict = {}):
    p = await P()
    actor = await get_actor(p, payload.get("token",""))
    await p.execute("delete from saved_pivots where id=$1 and owner_id=$2", uuid.UUID(pivot_id), actor["id"])
    return E({"deleted": True})

@app.post("/api/cases/{case_id}/attck")
async def map_attck(case_id: str, payload: dict):
    p = await P()
    c = await p.fetchrow("select id from cases where case_id=$1", case_id)
    if not c: return E(None, error="case not found")
    r = await p.fetchrow(
        "insert into attck_mappings(case_id,technique_id,technique_name,evidence,created_by) values($1,$2,$3,$4,$5) returning *",
        c["id"], payload["technique_id"], payload.get("technique_name",""),
        payload.get("evidence",""),
        uuid.UUID(payload["created_by"]) if payload.get("created_by") else None
    )
    return E(rd(r))

@app.get("/api/cases/{case_id}/attck")
async def get_attck(case_id: str, payload: dict = {}):
    c = await (await P()).fetchrow("select id from cases where case_id=$1", case_id)
    if not c: return E(None, error="case not found")
    rows = await (await P()).fetch("select * from attck_mappings where case_id=$1 order by created_at", c["id"])
    return E([rd(r) for r in rows])

# ═══════════════════════════════════════════════════════════
# CONTINUOUS AGENT CYCLE — live delta hunting against Elastic
# ═══════════════════════════════════════════════════════════
# Default: hunt EVERY non-system index so newly loaded data is found without reconfiguration.
# Operators can narrow this during setup (index selection) or in Admin → Agent Management.
HUNT_INDEXES = "*,-.*"

# role_string -> (display name, live Elastic query, default severity)
AGENT_QUERIES = {
    "new_domain_agent": ("New Domain Agent", "event.category:dns OR dns.question.name:* OR query.keyword:*", "medium"),
    "new_external_ip_agent": ("New External IP Agent", "destination.ip:* OR id.resp_h:* OR dest_ip:*", "medium"),
    "dga_agent": ("DGA Agent", "NXDOMAIN OR dns.response_code:NXDOMAIN", "medium"),
    "beaconing_agent": ("Beaconing Agent", "event.dataset:*conn* OR zeek.uid:* OR event.module:zeek", "medium"),
    "ja3_ja4_agent": ("JA3/JA4 Agent", "ja3:* OR tls.client.ja3:* OR event.dataset:*ssl*", "low"),
    "threat_intel_agent": ("Threat Intel Correlation Agent", "mimikatz OR rundll32.exe OR procdump OR lsass OR kxwn.lock", "high"),
    "sysmon_process_agent": ("Sysmon Process Anomaly Agent", "event.module:sysmon OR winlog.channel:\"Microsoft-Windows-Sysmon/Operational\" OR process.entity_id:*", "medium"),
    "windows_logon_agent": ("Windows Logon Anomaly Agent", "event.code:(4624 OR 4625 OR 4648) OR winlog.event_id:(4624 OR 4625 OR 4648)", "medium"),
    "powershell_agent": ("PowerShell Activity Agent", "powershell OR encodedcommand OR invoke-webrequest OR iex", "high"),
    "service_account_agent": ("Service Account Activity Agent", "event.code:4769 OR kerberos OR krbtgt", "medium"),
}


def signature_query(field: str, value: str) -> str:
    value = (value or "").strip()
    quoted = '"' + value.replace('"', '\\"') + '"'
    field = (field or "").strip()
    return f"{field}:{quoted}" if field else quoted


async def es_agent_search(query: str, use_simple: bool = False):
    """Count matching docs across the hunt index patterns and return (total, latest sample)."""
    pattern = (_agent_cycle_params.get("index_pattern") or HUNT_INDEXES).strip() or HUNT_INDEXES
    if use_simple:
        q = {"simple_query_string": {"query": query}}
    else:
        q = {"query_string": {"query": query, "default_field": "*"}}
    body = {"size": 1, "query": q, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], "track_total_hits": True}
    res = await es_request("GET", f"/{pattern}/_search?ignore_unavailable=true&allow_no_indices=true", body, timeout=15)
    hits = res.get("hits", {})
    total = hits.get("total", {})
    total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    rows = hits.get("hits", [])
    sample = rows[0].get("_source", {}) if rows else {}
    return total, sample


async def create_agent_event(p, sid, agent_role, agent_name, severity, query, total, delta, sample, extra_tags=None):
    """Insert a NEW event (unique id) for fresh telemetry matches found by an agent or signature."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    event_id = f"EVT-{snake(agent_role).upper().replace('_','-')}-{stamp}-{secrets.token_hex(2).upper()}"
    title_seed = f"{agent_name}: {delta} new matching event{'s' if delta != 1 else ''}"
    evidence = {
        "title": title_seed,
        "query": query,
        "new_match_count": delta,
        "total_match_count": total,
        "raw_sample": sample,
        "fallback_explanation": f"{agent_name} detected {delta} new matching events in live Elastic telemetry (total now {total}). Review the latest raw sample and correlate before escalation.",
    }
    ai = await openrouter_agent_summary(agent_role, evidence, severity)
    enrichment = [
        {"label": "Query", "value": query[:140], "color": "highlight"},
        {"label": "New Events", "value": str(delta), "color": "danger"},
        {"label": "Total Matching", "value": str(total), "color": "highlight"},
        {"label": "Model", "value": ai.get("model_used", "unknown"), "color": "highlight"},
    ]
    tags = [{"text": "Live Backend", "type": "intel"}, {"text": "Continuous Hunt", "type": "context"}] + (extra_tags or [])
    agent_sum = json.dumps({k: ai.get(k, "") for k in ("who", "what", "when", "where", "why", "how") if ai.get(k)})
    await p.execute(
        "insert into events(event_id,session_id,agent,severity,title,snippet,explanation,enrichment,tags,recommended_next_question,raw_log_sample,confidence,metadata,agent_summary) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) on conflict(event_id) do nothing",
        event_id,
        uuid.UUID(sid),
        agent_role,
        severity,
        ai["title"],
        f"{delta} new matching events observed by {agent_name}.",
        ai["explanation"],
        json.dumps(enrichment),
        json.dumps(tags),
        ai["recommended_next_question"],
        json.dumps(sample, default=str)[:8000],
        ai["confidence"],
        json.dumps({"count": total, "new": delta, "query": query, "model_used": ai.get("model_used")}),
        agent_sum,
    )
    return event_id


async def run_agent_cycle(p, sid: str, baseline_only: bool = False):
    """One hunting pass: built-in agents, enabled custom agents, and analyst signatures.
    Tracks per-agent match totals so NEW data in Elastic produces NEW alerts."""
    created = []
    # Built-in agents
    for role, (name, query, sev) in AGENT_QUERIES.items():
        try:
            total, sample = await es_agent_search(query)
        except Exception:
            continue
        prev = await p.fetchval("select last_total from agent_state where agent=$1", role)
        await p.execute(
            "insert into agent_state(agent,last_total,last_run_at) values($1,$2,now()) on conflict(agent) do update set last_total=excluded.last_total, last_run_at=now()",
            role, total,
        )
        if prev is None or baseline_only:
            continue
        if total > prev:
            created.append(await create_agent_event(p, sid, role, name, sev, query, total, total - int(prev), sample))
    # Enabled custom agents
    for r in await p.fetch("select * from custom_agents where enabled=true and archived_at is null"):
        focus = (r["detection_focus"] or r["name"] or "").strip()
        if not focus:
            continue
        key = "custom:" + r["role_string"]
        try:
            total, sample = await es_agent_search(focus, use_simple=True)
        except Exception:
            continue
        prev = await p.fetchval("select last_total from agent_state where agent=$1", key)
        await p.execute(
            "insert into agent_state(agent,last_total,last_run_at) values($1,$2,now()) on conflict(agent) do update set last_total=excluded.last_total, last_run_at=now()",
            key, total,
        )
        await p.execute("update custom_agents set last_run_at=now() where id=$1", r["id"])
        if prev is None or baseline_only:
            continue
        if total > prev:
            created.append(await create_agent_event(p, sid, r["role_string"], r["name"], r["severity_default"] or "medium", focus, total, total - int(prev), sample))
            await p.execute("update custom_agents set total_events_generated=coalesce(total_events_generated,0)+1 where id=$1", r["id"])
    # Analyst signatures: notify the creator when their signature pops
    for s in await p.fetch("select * from signatures where enabled=true"):
        query = signature_query(s["field"], s["value"])
        try:
            total, sample = await es_agent_search(query)
        except Exception:
            continue
        prev = int(s["last_total"] if s["last_total"] is not None else -1)
        hit = (prev < 0 and total > 0) or (prev >= 0 and total > prev)
        await p.execute(
            "update signatures set last_total=$2, last_run_at=now(), last_hit_at=case when $3 then now() else last_hit_at end, updated_at=now() where id=$1",
            s["id"], total, hit,
        )
        if baseline_only or not hit:
            continue
        delta = total if prev < 0 else total - prev
        agent_name = f"Signature: {s['name']}"
        tags = [{"text": f"Signature // {s['name']}", "type": "intel"}, {"text": f"Created by {s['created_by_name'] or 'analyst'}", "type": "context"}]
        event_id = await create_agent_event(p, sid, "signature_agent", agent_name, s["severity"] or "medium", query, total, delta, sample, extra_tags=tags)
        created.append(event_id)
        if s["created_by"]:
            try:
                await p.execute(
                    "insert into notifications(recipient_id,n_type,body,event_id) values($1,'signature',$2,$3)",
                    s["created_by"],
                    f"Your signature '{s['name']}' popped: {delta} new match{'es' if delta != 1 else ''} (total {total}). Alert {event_id} is yours to triage.",
                    event_id,
                )
            except Exception:
                pass
    return created


def get_agent_cycle():
    return _agent_cycle_params
_agent_cycle_params = {"interval_seconds": 120, "max_concurrent": 4, "last_run": 0, "enabled": True, "index_pattern": HUNT_INDEXES}

def set_agent_cycle(**kw):
    _agent_cycle_params.update(kw)

@app.get("/api/agents/cycle")
async def get_cycle(token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    last_cycle_at = await p.fetchval("select max(last_run_at) from agent_state")
    return E({**_agent_cycle_params, "last_cycle_at": ser(last_cycle_at)})

@app.post("/api/agents/cycle")
async def update_cycle(payload: dict):
    actor = await get_actor(await P(), payload.get("token",""))
    if actor["privilege_level"] != "admin":
        return E(None, error="admin required")
    if "interval_seconds" in payload:
        _agent_cycle_params["interval_seconds"] = max(30, int(payload["interval_seconds"]))
    if "enabled" in payload:
        _agent_cycle_params["enabled"] = bool(payload["enabled"])
    if "max_concurrent" in payload:
        _agent_cycle_params["max_concurrent"] = max(1, int(payload["max_concurrent"]))
    if "index_pattern" in payload:
        _agent_cycle_params["index_pattern"] = str(payload["index_pattern"]).strip() or HUNT_INDEXES
    await save_hunt_setting(await P())
    return E(_agent_cycle_params)


async def save_hunt_setting(p):
    await upsert_setting(p, "hunt", {
        "index_pattern": _agent_cycle_params["index_pattern"],
        "interval_seconds": _agent_cycle_params["interval_seconds"],
        "enabled": _agent_cycle_params["enabled"],
    })


async def load_hunt_setting(p):
    cfg = await get_setting(p, "hunt", {})
    if cfg.get("index_pattern"):
        _agent_cycle_params["index_pattern"] = cfg["index_pattern"]
    if cfg.get("interval_seconds"):
        _agent_cycle_params["interval_seconds"] = max(30, int(cfg["interval_seconds"]))
    if "enabled" in cfg:
        _agent_cycle_params["enabled"] = bool(cfg["enabled"])

# Background agent loop: re-hunts Elastic every N seconds and raises NEW alerts on new data
async def agent_cycle_loop():
    """Background task: run the live hunting cycle against the most recent active session."""
    while True:
        await asyncio.sleep(get_agent_cycle()["interval_seconds"])
        if not _agent_cycle_params["enabled"]:
            continue
        try:
            p = await P()
            sid = await p.fetchval("select id from hunt_sessions where status='active' order by updated_at desc limit 1")
            if not sid:
                continue
            created = await run_agent_cycle(p, str(sid))
            if created:
                print(f"agent_cycle: created {len(created)} new alerts: {created}")
        except Exception as exc:
            print(f"agent_cycle error: {exc}")
            await asyncio.sleep(30)

@app.on_event("startup")
async def startup_event():
    import asyncio
    asyncio.create_task(agent_cycle_loop())

# ═══════════════════════════════════════════════════════════
# CASE TEAM SHARING / ACL
# ═══════════════════════════════════════════════════════════
@app.post("/api/cases/{case_id}/teams")
async def share_case_with_team(case_id: str, payload: dict):
    p = await P()
    actor = await get_actor(p, payload.get("token",""))
    c = await p.fetchrow("select id from cases where case_id=$1 or id::text=$1", case_id)
    if not c: return E(None, error="case not found")
    if not await can_access_case(p, c["id"], actor): return E(None, error="access denied")
    # Only creator/admin/commander can share
    can_share = actor["privilege_level"] in ("admin", "commander") or "commander" in (actor.get("work_role") or "").lower()
    if not can_share: return E(None, error="only admins or commanders can share cases with teams")
    team_id = payload.get("team_id")
    if not team_id: return E(None, error="team_id required")
    try:
        await p.execute("insert into case_teams(case_id,team_id,added_by) values($1,$2,$3) on conflict do nothing", c["id"], uuid.UUID(team_id), actor["id"])
        await p.execute("insert into case_acl(case_id,entity_type,entity_id,granted_by) values($1,'team',$2,$3) on conflict do nothing", c["id"], uuid.UUID(team_id), actor["id"])
    except Exception: pass
    # Also list teams granted access
    teams = await p.fetch("select t.*, ct.added_at as shared_at from case_teams ct join teams t on t.id=ct.team_id where ct.case_id=$1", c["id"])
    return E({"shared": True, "teams": [rd(t) for t in teams]})

@app.get("/api/cases/{case_id}/teams")
async def get_case_teams(case_id: str, token: str = ""):
    p = await P()
    actor = await get_actor(p, token)
    c = await p.fetchrow("select id from cases where case_id=$1 or id::text=$1", case_id)
    if not c: return E(None, error="case not found")
    if not await can_access_case(p, c["id"], actor): return E(None, error="access denied")
    rows = await p.fetch("select t.id, t.team_display, t.team_type, t.number, t.location, ct.added_at from case_teams ct join teams t on t.id=ct.team_id where ct.case_id=$1 order by ct.added_at", c["id"])
    return E([rd(r) for r in rows])

@app.delete("/api/cases/{case_id}/teams/{team_id}")
async def revoke_case_team(case_id: str, team_id: str, payload: dict = {}):
    p = await P()
    actor = await get_actor(p, payload.get("token",""))
    c = await p.fetchrow("select id from cases where case_id=$1", case_id)
    if not c: return E(None, error="case not found")
    if not await can_access_case(p, c["id"], actor): return E(None, error="access denied")
    await p.execute("delete from case_teams where case_id=$1 and team_id=$2", c["id"], uuid.UUID(team_id))
    await p.execute("delete from case_acl where case_id=$1 and entity_type='team' and entity_id=$2", c["id"], uuid.UUID(team_id))
    return E({"revoked": True})
