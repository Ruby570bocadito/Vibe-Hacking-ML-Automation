# syntax=docker/dockerfile:1

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    gobuster \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.ai/install.sh | sh || echo "Ollama installation skipped (run separately)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p checkpoints logs reports plugins

RUN chmod +x main.py

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]

EXPOSE 11434

LABEL org.opencontainers.image.title="Vibe-Hacker"
LABEL org.opencontainers.image.description="Autonomous offensive security agent"
LABEL org.opencontainers.image.version="3.0"
