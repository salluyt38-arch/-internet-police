FROM python:3.12-slim

# Security: Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app

# Install minimal build deps and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Security: Create and switch to non-root service user
RUN useradd -u 10001 -m cyberagent && \
    chown -R cyberagent:cyberagent /app

USER cyberagent

EXPOSE 8080 5353/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/status || exit 1

CMD ["python", "main.py"]
