FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN mkdir -p /run/secrets
COPY --chown=10001:10001 sovagrid_hub /app/sovagrid_hub
COPY LICENSE ATTRIBUTION.md NOTICE /app/

# The verified server source bundle supplies this public digest at build time.
# Empty means the running image cannot prove a compatible bundle.
ARG SOVAGRID_BUNDLE_MANIFEST_SHA256=""
ENV SOVAGRID_BUNDLE_MANIFEST_SHA256=${SOVAGRID_BUNDLE_MANIFEST_SHA256}

USER 10001:10001
ENTRYPOINT ["python3", "-m", "sovagrid_hub"]
CMD ["--db", "/data/hub.sqlite", "serve", "--bind", "0.0.0.0", "--port", "8765"]
