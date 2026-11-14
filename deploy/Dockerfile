# One image for every container of the network mode; the compose command picks the role.
FROM python:3.12-slim

RUN pip install --no-cache-dir --retries 10 --timeout 60 \
        "fastapi==0.115.6" "uvicorn==0.34.0" "pydantic==2.10.4" \
    && useradd --uid 10001 --system --no-create-home --shell /usr/sbin/nologin icssim

WORKDIR /app
COPY icssim /app/icssim
COPY static /app/static
COPY tools /app/tools

# The gateway's policy file is exported from icssim/network.py at build time, so the
# container always enforces the same zone table and DPI rules as the simulator.
RUN python -m icssim export-policy --out /app/policy.json && chmod 0444 /app/policy.json

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER icssim
ENTRYPOINT ["python", "-m"]
