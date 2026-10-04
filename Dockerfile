FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcpgw ./mcpgw
COPY policy.yaml ./policy.yaml
COPY demo ./demo
ENV PYTHONUNBUFFERED=1
# The gateway speaks MCP over stdio; the control plane is exposed on 8765.
EXPOSE 8765
ENTRYPOINT ["python", "-m", "mcpgw.cli", "--policy", "policy.yaml", "--audit", "/data/audit.jsonl", "--control-host", "0.0.0.0", "--control-port", "8765", "--"]
CMD ["python", "demo/toy_server.py"]
