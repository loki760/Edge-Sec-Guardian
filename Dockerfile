FROM python:3.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 1000 developer

# The allowlist also admits the ML owner's modules when they are integrated.
COPY --chown=developer:developer *.py ./
COPY --chown=developer:developer data/ ./data/
RUN mkdir -p artifacts data/raw \
    && chown -R developer:developer artifacts data

USER developer

CMD ["python", "cli.py", "--help"]
