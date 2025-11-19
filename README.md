cd "C:\Users\LENOVO\Desktop\Aktif Projeler\SuspiciousLinkRadar"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8081 --no-reload --log-level info