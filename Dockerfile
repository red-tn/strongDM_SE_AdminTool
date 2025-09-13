FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY strongdm_manager.py .
COPY example_resources.csv .
COPY README.md .

ENV DISPLAY=:0

CMD ["python", "strongdm_manager.py"]
