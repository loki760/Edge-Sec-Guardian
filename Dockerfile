FROM python:3.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 1000 developer

COPY --chown=developer:developer extract_features.py make_sample_pcap.py test_extract.py ./
COPY --chown=developer:developer data/ ./data/

USER developer

CMD ["python", "extract_features.py", "--input", "data/sample.pcap", "--output", "data/features.csv"]
