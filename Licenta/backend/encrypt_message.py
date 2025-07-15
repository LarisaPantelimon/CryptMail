from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from datetime import datetime
import base64
from email import policy
from email.parser import BytesParser
import secrets
import json
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def build_the_message_structure(mime_message: str) -> dict:
    mime_message_bytes = mime_message.encode('utf-8') 
    message = BytesParser(policy=policy.default).parsebytes(mime_message_bytes)

    filenames = []
    for part in message.walk():
        if part.get_content_disposition() == 'attachment':
            filenames.append(part.get_filename())

    current_timestamp = datetime.now().isoformat()
    
    message_structure = {
        "files": filenames,
        "timestamp": current_timestamp,
        "message": mime_message
    }
    
    return message_structure
def calculate_hash_message(message):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message)
    return digest.finalize()

def signature_for_hash(message_hash, private_key):
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    
    return signature

def get_leading_two_octets(hash_result: bytes) -> bytes:
    return hash_result[:2]

def build_the_signature_part(message, pubkey_id, private_key):
    message_structure = build_the_message_structure(message)
    
    if isinstance(message_structure, dict):
        message_structure = json.dumps(message_structure)
    
    message_structure = message_structure.encode('utf-8')
    
    message_hash = calculate_hash_message(message_structure.encode('utf-8'))
    
    leading_two_octets = get_leading_two_octets(message_hash)

    signature = signature_for_hash(message_hash, private_key)

    current_timestamp = datetime.now().isoformat()

    signature_part = {
        "signature_timestamp": current_timestamp,
        "public_key_id": pubkey_id,
        "leading_octets_of_digest": leading_two_octets.hex(),
        "signature": signature.hex()
    }
    
    return signature_part

def build_blob_for_zip(message_part, signature_part):
    blob = {
        "signature_part": signature_part,
        "message_part": message_part
    }
    
    return blob

def compress_message(message: bytes) -> bytes:
    message_json = json.dumps(message)
    message_bytes = message_json.encode('utf-8')
    
    compressed_data = zlib.compress(message_bytes)

    return base64.b64encode(compressed_data).decode("utf-8")


def encrypt_aes_gcm(message):
    key = secrets.token_bytes(32)  # 256-bit key
    iv = secrets.token_bytes(12)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag

    encryption_params = {
        "key": key.hex(),
        "iv": iv.hex(),
        "tag": tag.hex()
    }

    # Returnez separat parametrii pentru a putea sa ii folosesc mai tarziu
    # ciphertext, encryption_params = encrypt_aes_gcm(message) pentru apelarea functiei
    return ciphertext.hex(), json.dumps(encryption_params)


def encrypt_symmetric_key_with_rsa(data: dict, rsa_public_key: RSAPublicKey) -> bytes:
    # Primesc ca parametru un dictionar care contine cheia simetrica, iv-ul si tagul
    # convertesc dictionarul intr un string json de bytes pentru a il putea cripta
    json_data = json.dumps(data).encode("utf-8")
    
    # criptez stringul folosind cheia publica a destinatarului
    encrypted_data = rsa_public_key.encrypt(
        json_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_data

def encrypted_symmetric_key(key_id, encryped_key):
    # Creez un dictionar care contine key id ul si cheia simetrica criptata cu cheia publica a destinatarului
    blob = {
        "key_id": key_id,
        "encrypted_symmetric_key": encryped_key
    }
    
    return blob

def construct_final_form_of_message(encrypted_key, encrypted_message):
    # Create a dictionary containing the encrypted symmetric key and encrypted message
    final_form = {
        "symmetric_key_enc": encrypted_key,
        "encrypted_message": encrypted_message
    }
    
    # Convert dictionary to JSON string
    json_string = json.dumps(final_form)
    
    # Encode the JSON string in base64
    base64_encoded = base64.b64encode(json_string.encode()).decode()
    
    return base64_encoded
    
    