import json, uuid, asyncio, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import asyncpg, httpx
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic_settings import BaseSettings
from redis.asyncio import Redis
class Settings(BaseSettings):
    database_url:str='postgresql://spotter:spotter-local-dev@postgres:5432/spotter'; redis_url:str='redis://redis:6379/0'; qdrant_url:str='http://qdrant:6333'; minio_endpoint:str='minio:9000'
settings=Settings(); pool=None; ROOT=Path(__file__).resolve().parents[1]; FRONTEND=ROOT/'frontend'
app=FastAPI(title='Spotter-Shooter API',version='0.1.0'); app.mount('/static',StaticFiles(directory=str(FRONTEND)),name='static')
def E(data=None,error=None,meta=None): return {'success': error is None,'data':data if data is not None else {},'error':error,'meta':meta or {}}
async def P():
    global pool
    if pool is None: pool=await asyncpg.create_pool(settings.database_url,min_size=1,max_size=10)
    return pool
@app.get('/')
async def root(): return FileResponse(FRONTEND/'deployment.html')
@app.get('/deployment.html')
async def deployment(): return FileResponse(FRONTEND/'deployment.html')
@app.get('/operations.html')
async def operations(): return FileResponse(FRONTEND/'operations.html')
async def ok_pg():
    try: return await (await P()).fetchval('select 1')==1
    except Exception: return False
async def ok_redis():
    try: r=Redis.from_url(settings.redis_url); await r.ping(); await r.aclose(); return True
    except Exception: return False
async def ok_http(url):
    try:
        async with httpx.AsyncClient(timeout=2) as c: return (await c.get(url)).status_code<500
    except Exception: return False
@app.get('/api/health')
async def health():
    s={'Postgres':await ok_pg(),'Redis':await ok_redis(),'Docling':True,'Qdrant':await ok_http(settings.qdrant_url+'/healthz'),'MinIO':await ok_http('http://'+settings.minio_endpoint+'/minio/health/live'),'LiteLLM':True,'Zeek Worker':True}
    return E({'status':'green' if all(s.values()) else 'degraded','services':s})
BUILTIN=[('New Domain Agent','new_domain_agent','Zeek DNS','network',True),('New External IP Agent','new_external_ip_agent','Zeek Conn','network',True),('DGA Agent','dga_agent','Zeek DNS','network',True),('Beaconing Agent','beaconing_agent','Zeek Conn','network',True),('JA3/JA4 Agent','ja3_ja4_agent','Zeek SSL','network',True),('Threat Intel Correlation Agent','threat_intel_agent','All sources','network',True),('ASOM Drafting Agent','asom_drafting_agent','Confirmed findings','network',True),('Sysmon Process Anomaly Agent','sysmon_process_agent','Sysmon','host',False),('Windows Logon Anomaly Agent','windows_logon_agent','Windows Event Log','host',False),('PowerShell Activity Agent','powershell_agent','Sysmon / Windows Event Log','host',False),('Service Account Activity Agent','service_account_agent','Windows Event Log','host',False)]
def ser(v):
    if isinstance(v,uuid.UUID): return str(v)
    if hasattr(v,'isoformat'): return v.isoformat()
    return v
def rd(r): return {k:ser(v) for k,v in dict(r).items()}
def snake(s): return re.sub('_+','_',re.sub(r'[^a-z0-9]+','_',s.lower())).strip('_')
@app.post('/api/setup/session')
async def session(payload:dict={}):
    r=await (await P()).fetchrow("insert into hunt_sessions(config,status,created_by_role) values($1,'setup',$2) returning *",json.dumps(payload or {}),payload.get('role','admin'))
    return E(rd(r))
@app.post('/api/setup/telemetry/test')
async def telemetry(payload:dict): return E({'connected':True,'indexes':['botsv3-raw','apt29-endpoint','apt3-endpoint','lsass-events'],'latency_ms':42})
@app.post('/api/setup/model/test')
async def model(payload:dict): return E({'provider':payload.get('provider','OpenRouter'),'model':payload.get('model','local-demo'),'latency_ms':380,'tokens_per_sec':42.7})
@app.get('/api/setup/data')
async def data(): return E({'sources':[{'name':'Zeek DNS','count':7804},{'name':'Zeek Conn','count':10237},{'name':'Sysmon','count':1006930},{'name':'Windows Events','count':354229}], 'recommendation':'Start with network telemetry only; add host telemetry after analyst review.'})
@app.post('/api/documents/upload')
async def upload(file:UploadFile=File(...), session_id:Optional[str]=Form(None), doc_type:str=Form('Mission Document')):
    p=await P()
    if not session_id: session_id=str(await p.fetchval("insert into hunt_sessions(status,config) values('setup',$1) returning id",'{}'))
    r=await p.fetchrow('insert into documents(session_id,filename,doc_type,minio_key,parsed,indexed) values($1,$2,$3,$4,true,true) returning *',uuid.UUID(session_id),file.filename,doc_type,'local/'+file.filename)
    return E(rd(r))
def _jsonish(v):
    if isinstance(v, str):
        try: return json.loads(v)
        except Exception: return []
    return v or []
def ev(r):
    d=dict(r); enr=_jsonish(d['enrichment']); tags=_jsonish(d['tags'])
    return {'id':d['event_id'],'event_id':d['event_id'],'agent':d['agent'],'severity':d['severity'],'sev':{'critical':'crit','high':'high','medium':'medium','low':'low'}[d['severity']],'sevLabel':d['severity'].title(),'title':d['title'],'snippet':d['snippet'],'explanation':d['explanation'],'enrichment':[{'label':x.get('label'),'val':x.get('value'),'cls':x.get('color','neutral'),**x} for x in enr if isinstance(x,dict)],'tags':[{'label':x.get('text'),'cls':x.get('type'),**x} for x in tags if isinstance(x,dict)],'nextQ':d['recommended_next_question'],'log':d['raw_log_sample'],'confidence':float(d['confidence']),'status':d['status']}
@app.get('/api/events')
async def events(limit:int=100): return E([ev(r) for r in await (await P()).fetch('select * from events order by created_at desc limit $1',limit)])
@app.patch('/api/events/{event_id}/dismiss')
async def dismiss(event_id:str): await (await P()).execute("update events set status='dismissed' where event_id=$1",event_id); return E({'event_id':event_id})
@app.patch('/api/events/{event_id}/escalate')
async def escalate(event_id:str):
    p=await P(); e=await p.fetchrow('select * from events where event_id=$1',event_id); cid='CASE-'+event_id.split('-')[-1]
    if e: await p.execute("insert into cases(case_id,session_id,name,owner,narrative_summary,status) values($1,$2,$3,'SOC Lead',$4,'open') on conflict(case_id) do nothing",cid,e['session_id'],e['title'],e['explanation']); await p.execute("update events set status='escalated' where event_id=$1",event_id)
    return E({'case_id':cid})
@app.get('/api/cases')
async def cases(): return E([{'id':r['case_id'],'name':r['name'],'owner':r['owner'],'summary':r['narrative_summary'],'status':r['status']} for r in await (await P()).fetch('select * from cases order by created_at desc')])
@app.get('/api/agents')
async def agents(): return E({'built_in':[{'name':n,'role_string':r,'telemetry_source':t,'tier':tier,'enabled':en} for n,r,t,tier,en in BUILTIN], 'custom':[rd(r) for r in await (await P()).fetch('select * from custom_agents where archived_at is null order by created_at desc')]})
@app.post('/api/agents/custom')
async def custom(payload:dict):
    role=payload.get('role_string') or snake(payload['name'])
    r=await (await P()).fetchrow('insert into custom_agents(name,role_string,description,telemetry_source,tier,severity_default,confidence_threshold,detection_focus,key_fields,tag_rules,system_prompt_override,enabled,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) returning *',payload['name'],role,payload.get('description',''),payload.get('telemetry_source','Custom Query'),payload.get('tier','network'),payload.get('severity_default','medium'),float(payload.get('confidence_threshold',.6)),payload['detection_focus'],json.dumps(payload.get('key_fields',[])),json.dumps(payload.get('tag_rules',[])),payload.get('system_prompt_override'),bool(payload.get('enabled',False)),payload.get('created_by','admin'))
    return E(rd(r))
@app.post('/api/agents/custom/{agent_id}/test')
async def test_agent(agent_id:str): return E({'findings':[{'event_id':'DRYRUN-001','severity':'medium','title':'Custom Agent Preview','confidence':0.74}], 'histogram':[{'bucket':'0.7-0.8','count':1}]})
@app.get('/admin/agents')
async def admin(): return HTMLResponse('<!doctype html><title>Spotter-Shooter Admin</title><body style="background:#0a0c0e;color:#c8d4da;font-family:monospace"><h1 style="color:#e8a427">ADMIN // CUSTOM AGENTS</h1><form onsubmit="save();return false"><input id=name placeholder="Agent Name" value="Kerberoasting Detection Agent"><br><textarea id=focus>Look for Windows Event 4769 requests using RC4 encryption.</textarea><br><button>Create Agent</button></form><pre id=out></pre><script>async function save(){let b=await (await fetch(\'/api/agents/custom\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({name:name.value,telemetry_source:\'Windows Event Log\',tier:\'host\',detection_focus:focus.value})})).json();out.textContent=JSON.stringify(b,null,2)}</script></body>')
async def seed(sid):
    p=await P(); samples=[('EVT-0041','beaconing_agent','critical','C2 Beacon Detected — WKSTN-042'),('EVT-0042','dga_agent','high','High Entropy DNS Burst — FIN-WS-017'),('EVT-0043','powershell_agent','high','Encoded PowerShell Execution — ADM-014')]
    for eid,agent,sev,title in samples:
        await p.execute('insert into events(event_id,session_id,agent,severity,title,snippet,explanation,enrichment,tags,recommended_next_question,raw_log_sample,confidence) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) on conflict(event_id) do nothing',eid,uuid.UUID(sid),agent,sev,title,'10.4.22.17 → 185.220.101.47 every 300s','Agent surfaced a high-signal anomaly requiring analyst review.',json.dumps([{'label':'Source IP','value':'10.4.22.17','color':'highlight'}]),json.dumps([{'text':'Mission Intel Match','type':'intel'}]),'Pivot across DNS, conn, Sysmon and Windows logs for the prior six hours.',json.dumps({'event':eid}),.93)
@app.post('/api/setup/launch')
async def launch(payload:dict={}):
    r=await (await P()).fetchrow("insert into hunt_sessions(status,config) values('active',$1) returning *",json.dumps(payload)); await seed(str(r['id'])); return E({'session_id':str(r['id']),'status':'active'})
@app.websocket('/ws/events/{session_id}')
async def ws(ws:WebSocket,session_id:str):
    await ws.accept()
    try:
        while True: await asyncio.sleep(10); await ws.send_json({'type':'heartbeat','ts':datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect: pass
