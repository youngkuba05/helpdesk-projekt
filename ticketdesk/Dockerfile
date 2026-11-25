FROM python:3.11-slim

WORKDIR /code

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --only-binary=:all: \
  -r /code/requirements.txt

RUN python -m pip uninstall -y pip setuptools wheel

RUN groupadd --gid 10001 appgroup \
  && useradd --uid 10001 --gid appgroup --shell /usr/sbin/nologin --no-create-home appuser

COPY --chown=appuser:appgroup ./app /code/app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
