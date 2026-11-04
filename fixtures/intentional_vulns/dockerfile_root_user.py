FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
USER root  # INSECURE: runs as root
CMD ["python", "app.py"]