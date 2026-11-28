FROM python:3.12.15-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=2
WORKDIR /app
RUN apt-get update -qq && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-runtime.lock /app/requirements-runtime.lock
RUN pip install --no-cache-dir --no-compile --only-binary=:all: --require-hashes \
    -r /app/requirements-runtime.lock
COPY docs/development-runtime/predict.py /app/predict.py
USER 65532:65532
ENTRYPOINT ["python", "-B", "/app/predict.py"]
