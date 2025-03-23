import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt_server import app, generate_rsa_key, clean_up_expired_keys
import sqlite3
import base64

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    """Clean database before each test"""
    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()
    yield

def test_jwks():
    generate_rsa_key()
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert len(response.json()["keys"]) == 1

def test_auth():
    generate_rsa_key()
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()

def test_expired_auth():
    generate_rsa_key(expired=True)
    response = client.post("/auth?expired=true")
    token = response.json()["token"]
    
    header = jwt.get_unverified_header(token)
    jwks = client.get("/.well-known/jwks.json").json()
    
    # Finds matching key
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    
    # Fixes syntax for base64 padding
    n = key["n"] + "=" * (-len(key["n"]) % 4)
    e = key["e"] + "=" * (-len(key["e"]) % 4)
    
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(n), "big"),
        int.from_bytes(base64.urlsafe_b64decode(e), "big")
    ).public_key()

    with pytest.raises(JWTError):
        jwt.decode(token, public_key, algorithms=["RS256"])

def test_key_cleanup():
    kid = generate_rsa_key(expired=True)
    clean_up_expired_keys()
    
    jwks = client.get("/.well-known/jwks.json").json()
    assert kid not in [k["kid"] for k in jwks["keys"]]

def test_invalid_methods():
    assert client.put("/.well-known/jwks.json").status_code == 405
    assert client.get("/auth").status_code == 405
