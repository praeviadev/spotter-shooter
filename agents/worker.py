import os
from arq.connections import RedisSettings
class DynamicAgent:
    def __init__(self, agent_config): self.agent_role=agent_config['role_string']; self.agent_config=agent_config
    def load_system_prompt(self, role, config): return 'Return JSON only. Focus: '+self.agent_config.get('detection_focus','')
async def beaconing_agent(ctx, session_id='demo'): return {'event_id':'EVT-DEMO'}
class WorkerSettings:
    redis_settings=RedisSettings.from_dsn(os.getenv('REDIS_URL','redis://redis:6379/0'))
    functions=[beaconing_agent]
