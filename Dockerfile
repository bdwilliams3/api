FROM python:3.9-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt
COPY . .

FROM gcr.io/distroless/python3-debian11:nonroot
WORKDIR /app

COPY --from=builder /root/.local /home/nonroot/.local
COPY --from=builder /app /app

ENV PYTHONPATH=/home/nonroot/.local/lib/python3.9/site-packages
ENV PATH=/home/nonroot/.local/bin:$PATH

EXPOSE 8080
ENTRYPOINT ["python", "app.py"]