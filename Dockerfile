# Python 3.12 жеңіл базалық кескіні
FROM python:3.12-slim

# Жұмыс каталогы
WORKDIR /app

# Жүйелік тәуелділіктерді жаңарту және артықшылығы жоқ пайдаланушы құру (Non-Root User)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 cloudsec \
    && useradd -u 10001 -g cloudsec -s /bin/bash -m cloudsec

# Тәуелділіктерді орнату
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Жоба кодын көшіру және пайдаланушы құқықтарын бекіту
COPY . .
RUN chown -R cloudsec:cloudsec /app

# Қауіпсіздік талабы: Root емес пайдаланушы режиміне ауысу (Least Privilege)
USER cloudsec

# Веб-портты ашу
EXPOSE 8000

# FastAPI серверін қауіпсіз іске қосу
CMD ["python", "scanner.py", "--web", "--host", "0.0.0.0", "--port", "8000"]
