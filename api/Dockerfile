FROM python:3.11-slim
WORKDIR /app
COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY api /app/api
COPY frontend /app/frontend
EXPOSE 8080
CMD ["uvicorn","api.main:app","--host","0.0.0.0","--port","8080"]
