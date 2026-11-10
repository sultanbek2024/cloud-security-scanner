# Python 3.12 жеңіл базалық кескіні
FROM python:3.12-slim

# Жұмыс каталогы
WORKDIR /app

# Жүйелік тәуелділіктерді жаңарту
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Тәуелділіктерді орнату
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Жоба кодын көшіру
COPY . .

# Веб-портты ашу
EXPOSE 8000

# FastAPI серверін іске қосу
CMD ["python", "scanner.py", "--web", "--port", "8000"]
