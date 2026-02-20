# Stage 1: Builder - installs dependencies into /install prefix
FROM python:3.12-slim-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install --only-binary=:all: -r requirements.txt
COPY . .

# Stage 2: Distroless runtime - no shell, runs as nonroot uid 65532
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app

# Copy installed packages and app code from builder
COPY --from=builder /install /usr/local
COPY --from=builder /app /app

# Point Python to the installed packages
ENV PYTHONPATH="/usr/local/lib/python3.12/site-packages:/app"

USER 65532
EXPOSE 8080
ENTRYPOINT ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=8080"]