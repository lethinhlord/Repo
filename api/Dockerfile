FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-runtime.lock /app/requirements-runtime.lock
RUN pip install --no-cache-dir --no-compile --only-binary=:all: --require-hashes \
    -r /app/requirements-runtime.lock

COPY api /app/api
COPY ml /app/ml
COPY config /app/config

EXPOSE 8000

CMD ["uvicorn", "api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
