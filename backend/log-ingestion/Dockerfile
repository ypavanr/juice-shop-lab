FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

EXPOSE 5001

CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "5001", \
     "--workers", "2", \
     "--log-level", "info"]
