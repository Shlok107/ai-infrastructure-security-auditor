FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
Privileged: true  # INSECURE: privileged container
CMD ["python", "app.py"]