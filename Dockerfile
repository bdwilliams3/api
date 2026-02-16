# Stage 1: The Builder (Debian 11 to match Distroless)
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
COPY requirements.txt .

# Install to /install prefix (Standardizes the path)
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

# Stage 2: The Final Distroless Image
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app

# Copy libraries to /usr/local (standard Python path)
COPY --from=builder /install /usr/local
COPY --from=builder /app /app
ENV PYTHONPATH="/usr/local/lib/python3.9/site-packages:/app"

# Step 11 & 12 remain the same
USER 65532
EXPOSE 8080

# Step 13: Use the -m flag to run your app. 
# This helps Python resolve modules in the current directory better
ENTRYPOINT ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=8080"]
# OR if you prefer staying with your app.py:
# ENTRYPOINT ["python3", "app.py"]