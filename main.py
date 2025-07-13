from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
from Crypto.Cipher import AES

app = FastAPI(title="CryptexMaster Backend API")

class TextInput(BaseModel):
    text: str
    key: str = ""

@app.post("/encrypt/base64")
def encrypt_base64(data: TextInput):
    try:
        encoded = base64.b64encode(data.text.encode()).decode()
        return {"result": encoded}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt/base64")
def decrypt_base64(data: TextInput):
    try:
        decoded = base64.b64decode(data.text.encode()).decode()
        return {"result": decoded}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid Base64 input")

@app.post("/encrypt/aes")
def encrypt_aes(data: TextInput):
    try:
        key = data.key.encode().ljust(32, b'\x00')[:32]
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.text.encode())
        result = base64.b64encode(nonce + ciphertext).decode()
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt/aes")
def decrypt_aes(data: TextInput):
    try:
        key = data.key.encode().ljust(32, b'\x00')[:32]
        raw = base64.b64decode(data.text.encode())
        nonce = raw[:16]
        ciphertext = raw[16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt(ciphertext).decode()
        return {"result": decrypted}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Invalid AES input or key")
