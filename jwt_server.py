import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Query
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# Initializes FastAPI app
app = FastAPI()

# SQLites database file to store RSA private keys
DB_FILE = "totally_not_my_privateKeys.db"
KEY_EXPIRY_HOURS = 1  # Keys are valid for 1 hour

# Initializes the database and create table if not exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid TEXT PRIMARY KEY,      -- unique key ID
                key BLOB NOT NULL,         -- private key in PEM format
                exp INTEGER NOT NULL       -- expiration timestamp
            )
        """)
        conn.commit()

init_db()  # Calls database initializer on startup

# Generates a new RSA key pair and store the private key in the database
def generate_rsa_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    kid = str(uuid.uuid4())  # Generates a unique Key ID
    expiry = datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRY_HOURS)

    # Optionally make this key expired (for testing)
    if expired:
        expiry = datetime.now(timezone.utc) - timedelta(hours=1)

    # Serializes private key to PEM format (unencrypted)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Stores key in the database
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)",
                     (kid, private_pem, int(expiry.timestamp())))
        conn.commit()

    return kid

# Retrieves a valid or expired private key from the database
def get_private_key(expired=False):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        if expired:
            # Gets most recent expired key
            cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                           (datetime.now(timezone.utc).timestamp(),))
        else:
            # Gets earliest valid (non-expired) key
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
                           (datetime.now(timezone.utc).timestamp(),))
        result = cursor.fetchone()

    if not result:
        return None, None

    # Deserializes PEM to RSA private key object
    return result[0], serialization.load_pem_private_key(result[1], password=None)

# Auths endpoint to generate a JWT signed by a valid or expired key
@app.post("/auth")
def auth(expired: bool = Query(False)):
    kid, private_key = get_private_key(expired)
    if not private_key:
        raise HTTPException(status_code=500, detail="No valid private keys available")

    # Sets token expiry time (past if expired=True)
    expiry_time = datetime.now(timezone.utc) + timedelta(hours=1)
    if expired:
        expiry_time = datetime.now(timezone.utc) - timedelta(hours=1)

    # Serializes the private key to PEM for signing
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Creates a JWT using RS256 and embed the kid in the header
    token = jwt.encode(
        {"sub": "user", "exp": expiry_time.timestamp()},
        private_pem,
        algorithm="RS256",
        headers={"kid": kid}
    )

    return {"jwt": token}

# JWKS endpoint to expose all current valid public keys
@app.get("/.well-known/jwks.json")
def jwks():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Gets all non-expired keys
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?",
                       (datetime.now(timezone.utc).timestamp(),))
        rows = cursor.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No valid keys found")

    keys = []
    for kid, private_pem in rows:
        # Loads private key and extract public key
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Converts modulus (n) to base64 URL-safe format (remove padding)
        n = base64.urlsafe_b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        ).decode().rstrip("=")

        # Constructs JWKS-compatible key entry
        keys.append({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": n,
            "e": "AQAB"  # standards public exponent 65537 in base64
        })

    return {"keys": keys}

# Deletes expired keys from the database
def clean_up_expired_keys():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM keys WHERE exp <= ?",
                     (datetime.now(timezone.utc).timestamp(),))
        conn.commit()

# On startup, creates one expired and one valid key
generate_rsa_key(expired=True)  # Creates an expired key for testing
generate_rsa_key()              # Creates a valid key for normal operation
