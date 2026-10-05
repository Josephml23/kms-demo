"""
Cifrado en sobre (Envelope Encryption) con AWS KMS
--------------------------------------------------
Idea: KMS guarda una LLAVE MAESTRA que nunca sale de AWS. Para cada mensaje,
KMS genera una LLAVE DE DATOS (en claro + cifrada con la maestra). Ciframos el
mensaje con la llave en claro, la destruimos, y guardamos en un "sobre" el
mensaje cifrado + la llave cifrada. Para abrirlo, KMS descifra la llave.

Requisitos: pip install boto3 cryptography   |   aws configure (Access Key + Secret Key)
"""
import boto3, json, os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64 = lambda b: base64.b64encode(b).decode()            # bytes -> texto (para guardar en JSON)
kms = boto3.client("kms", region_name="us-east-1")      # 1. CONEXIÓN a KMS usando tu Access Key de AWS


def cifrar(mensaje, key_id, archivo="sobre.json"):
    dk = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")  # 2. KMS crea la llave de datos (claro + cifrada)
    nonce = os.urandom(12)                                       # valor aleatorio único que exige AES-GCM
    cifrado = AESGCM(dk["Plaintext"]).encrypt(nonce, mensaje.encode(), None)  # 3. CIFRAR el mensaje
    del dk["Plaintext"]                                          # 4. DESTRUIR la llave en claro
    sobre = {"llave_cifrada": b64(dk["CiphertextBlob"]), "nonce": b64(nonce), "mensaje_cifrado": b64(cifrado)}
    json.dump(sobre, open(archivo, "w"), indent=2)               # 5. GUARDAR el sobre digital
    return sobre


def descifrar(archivo="sobre.json"):
    s = {k: base64.b64decode(v) for k, v in json.load(open(archivo)).items()}  # 6. ABRIR el sobre
    llave = kms.decrypt(CiphertextBlob=s["llave_cifrada"])["Plaintext"]       # KMS descifra la llave de datos
    mensaje = AESGCM(llave).decrypt(s["nonce"], s["mensaje_cifrado"], None).decode()  # 7. DESCIFRAR el mensaje
    print("Llave de datos:", b64(llave), "\nMensaje:", mensaje)
    return mensaje


if __name__ == "__main__":
    key_id = kms.create_key(Description="Llave maestra demo")["KeyMetadata"]["KeyId"]  # llave maestra en KMS
    print("Sobre:", json.dumps(cifrar("Hola, este es un mensaje secreto", key_id), indent=2))
    descifrar()
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)  # 8. DESTRUIR la llave maestra (AWS exige 7-30 días)
