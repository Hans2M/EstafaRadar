from fastapi.testclient import TestClient
from app import engine
from app.main import app
client = TestClient(app)

def test_health():
    assert client.get('/api/v1/health').json()['safe_inspection'] is True

def test_invalid_protocol():
    data = client.post('/api/v1/analyze/url', json={'value':'javascript:alert(1)'}).json()
    assert data['visited_destination'] is False
    assert data['verdict'] != 'bajo'

def test_url_unknown_not_safe():
    data = client.post('/api/v1/analyze/url', json={'value':'https://example.com'}).json()
    assert data['verdict'] == 'no_concluyente'
    assert 'category' in data

def test_message_otp():
    data = client.post('/api/v1/analyze/message', json={'value':'Urgente, comparte tu codigo OTP ahora'}).json()
    assert data['verdict'] == 'alto'

def test_qr_not_opened():
    data = client.post('/api/v1/analyze/qr', json={'value':'https://example.com'}).json()
    assert data['visited_destination'] is True
    assert data['page_title'] == 'Example Domain'

def test_restricted_page_is_not_presented_as_safe(monkeypatch):
    monkeypatch.setattr(engine, '_inspect_page_browser', lambda _: {
        'final_url': 'https://example.com',
        'status': 403,
        'title': 'Just a moment...',
        'text': 'Checking your browser before accessing the site.',
        'browser_inspected': True,
    })
    data = client.post('/api/v1/analyze/url', json={'value':'https://example.com'}).json()
    assert data['verdict'] == 'no_concluyente'
    assert data['category'] == 'acceso restringido / protección anti-bot'
    assert any(f['code'] == 'ACCESS_RESTRICTED' for f in data['findings'])

def test_unofficial_streaming_title_gets_warning(monkeypatch):
    monkeypatch.setattr(engine, '_inspect_page_browser', lambda _: {
        'final_url': 'https://example.com',
        'status': 200,
        'title': 'Cuevana 3 - Ver Películas Gratis, Series y Anime en HD Online',
        'text': '',
        'browser_inspected': True,
    })
    data = client.post('/api/v1/analyze/url', json={'value':'https://example.com'}).json()
    assert data['verdict'] == 'moderado'
    assert data['score'] == 60
    assert data['category'] == 'entretenimiento no oficial'
    assert any(f['code'] == 'PIRACY_SIGNALS' for f in data['findings'])
