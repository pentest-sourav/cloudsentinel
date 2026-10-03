FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Run the API as a non-root application user.
RUN groupadd --system cloudsentinel     && useradd --system --gid cloudsentinel --create-home cloudsentinel

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY backend ./backend
COPY engine ./engine
COPY scanner ./scanner
COPY reporting ./reporting
COPY database ./database
COPY frontend ./frontend
COPY tests ./tests
COPY pyproject.toml .

RUN chown -R cloudsentinel:cloudsentinel /app

USER cloudsentinel

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
