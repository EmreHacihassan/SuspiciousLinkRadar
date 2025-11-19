# Aşama 1: Builder (Derleme)
FROM python:3.10-slim as builder

WORKDIR /app

# Gereksinimleri kopyala ve kur (User flag ile)
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Aşama 2: Final (Çalıştırma - Hafif ve Güvenli)
FROM python:3.10-slim

WORKDIR /app

# Ortam değişkenlerini ayarla
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH=/root/.local/bin:

# Builder aşamasından kütüphaneleri al
COPY --from=builder /root/.local /root/.local

# Kaynak kodları kopyala
COPY . .

# Root olmayan kullanıcı oluştur ve geç (Güvenlik)
RUN useradd -m appuser
USER appuser

# API portunu dışarı aç
EXPOSE 8081

# Uygulamayı başlat (Gunicorn ile Production-Ready)
# Not: Gunicorn yoksa requirements.txt'ye eklenmeli veya uvicorn kullanılmalı.
# Şimdilik güvenli olması için standart uvicorn komutunu kullanıyoruz.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
