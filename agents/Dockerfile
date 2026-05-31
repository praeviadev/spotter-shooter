FROM python:3.11-slim
WORKDIR /app
COPY agents/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY agents /app/agents
CMD ["arq","agents.worker.WorkerSettings"]
