import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture(scope="session")
def client():
    return TestClient(app)

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert "status" in r.json()

def test_predict_invalid(client):
    r = client.post("/predict", json={"url": ""})
    assert r.status_code == 400

def test_predict_without_model(client):
    # Model yoksa 503, varsa (eğitim yapıldıysa) 200 bekleriz
    from app.main import DEFAULT_MODEL_PATH
    if DEFAULT_MODEL_PATH.exists():
        pytest.skip("Model mevcut, bu negatif test atlandı.")
    r = client.post("/predict", json={"url": "https://example.com"})
    assert r.status_code in (503, 200)
