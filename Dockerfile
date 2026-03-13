# ── Stage 1: dependency builder ───────────────────────────────────
FROM python:3.10-slim AS builder

WORKDIR /app

# Install dependencies into a user-local prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Stage 2: production runtime ───────────────────────────────────
FROM python:3.10-slim AS runtime

WORKDIR /app

# Copy installed packages from the builder stage
COPY --from=builder /root/.local /root/.local

# Ensure user-installed scripts are on PATH
ENV PATH=/root/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy application source
COPY app.py scanner.py ./
COPY templates/ templates/

# Non-root user — defence in depth
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app
USER appuser

# Cloud Run / gunicorn listen on 8080 by default
EXPOSE 8080

# 2 workers; 120s timeout accommodates slow LLM responses
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
