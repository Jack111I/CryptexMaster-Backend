import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import string

# --- Vigenère Cipher ---
def vigenere_encrypt(plain_text, key):
    key = key.upper()
    result = ""
    for i, c in enumerate(plain_text):
        if c.isalpha():
            shift = ord(key[i % len(key)]) - 65
            base = 65 if c.isupper() else 97
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    return result

def vigenere_decrypt(cipher_text, key):
    key = key.upper()
    result = ""
    for i, c in enumerate(cipher_text):
        if c.isalpha():
            shift = ord(key[i % len(key)]) - 65
            base = 65 if c.isupper() else 97
            result += chr((ord(c) - base - shift) % 26 + base)
        else:
            result += c
    return result

# --- ROT13 ---
@app.post("/encrypt/rot13")
def encrypt_rot13(data: TextInput):
    return {"result": data.text.translate(str.maketrans(string.ascii_letters,
            string.ascii_letters[13:] + string.ascii_letters[:13]))}

@app.post("/decrypt/rot13")
def decrypt_rot13(data: TextInput):
    return encrypt_rot13(data)  # Same as encrypt

# --- XOR ---
@app.post("/encrypt/xor")
def encrypt_xor(data: TextInput):
    key = data.key or "key"
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data.text))
    return {"result": base64.b64encode(encrypted.encode()).decode()}

@app.post("/decrypt/xor")
def decrypt_xor(data: TextInput):
    try:
        decoded = base64.b64decode(data.text.encode()).decode()
        key = data.key or "key"
        decrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(decoded))
        return {"result": decrypted}
    except:
        raise HTTPException(status_code=400, detail="Invalid XOR input")

# --- Hashing ---
@app.post("/hash")
def hash_text(data: TextInput):
    return {
        "md5": hashlib.md5(data.text.encode()).hexdigest(),
        "sha256": hashlib.sha256(data.text.encode()).hexdigest()
    }

# --- Vigenère ---
@app.post("/encrypt/vigenere")
def encrypt_vigenere(data: TextInput):
    return {"result": vigenere_encrypt(data.text, data.key)}

@app.post("/decrypt/vigenere")
def decrypt_vigenere(data: TextInput):
    return {"result": vigenere_decrypt(data.text, data.key)}

# --- RSA KeyGen + Encrypt/Decrypt ---
@app.get("/rsa/keypair")
def rsa_keygen():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return {"private": private_key, "public": public_key}

class RSAInput(BaseModel):
    text: str
    key: str

@app.post("/rsa/encrypt")
def rsa_encrypt(data: RSAInput):
    key = RSA.import_key(data.key.encode())
    cipher = PKCS1_OAEP.new(key)
    enc = cipher.encrypt(data.text.encode())
    return {"result": base64.b64encode(enc).decode()}

@app.post("/rsa/decrypt")
def rsa_decrypt(data: RSAInput):
    try:
        key = RSA.import_key(data.key.encode())
        cipher = PKCS1_OAEP.new(key)
        dec = cipher.decrypt(base64.b64decode(data.text))
        return {"result": dec.decode()}
    except:
        raise HTTPException(status_code=400, detail="Invalid RSA input or key")
