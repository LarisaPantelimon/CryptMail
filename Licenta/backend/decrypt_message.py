import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zlib

# 1. Decodific din Base64 pentru a putea prelucra mesajul
def decode_final_form_of_message(encoded_string):
    # Decodez din base64
    json_string = base64.b64decode(encoded_string).decode()
    
    # Convertesc inapoi la JSON
    final_form = json.loads(json_string)
    
    return final_form

# 2. Verific daca key-id-ul din mesaj este acelasi cu key-id-ul meu
def verify_pubkey_of_receiver(final_form, my_keyid):
    #verific daca key-id ul din mesaj este acelasi cu key-id ul meu:
    if final_form.get("symmetric_key_enc").get("key_id") == my_keyid:
        return True
    else:
        return False
    
# 3. Extrage cheia simetrica criptata din mesaj si o decriptez
def decrypt_symmetric_key_with_rsa(encrypted_data, rsa_private_key):
    # Decriptez datele folosind cheia privata
    decrypted_json = rsa_private_key.decrypt(
        encrypted_data.get("symmetric_key_enc").get("encrypted_symmetric_key"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Convert JSON string back to a dictionary
    decrypted_data = json.loads(decrypted_json.decode("utf-8"))
    
    # Convert hex strings back to bytes
    decrypted_data["key"] = bytes.fromhex(decrypted_data["key"])
    decrypted_data["iv"] = bytes.fromhex(decrypted_data["iv"])
    decrypted_data["tag"] = bytes.fromhex(decrypted_data["tag"])

    return decrypted_data  # Returns the dictionary with original binary values

# 4. Decriptez mesajul folosind cheia simetrica    
def decrypt_message(message, encryption_params):
    # Extract decryption parameters
    key = encryption_params["key"]  # Already in bytes
    iv = encryption_params["iv"]  # Already in bytes
    tag = encryption_params["tag"]  # Already in bytes

    encrypted_message = message.get("encrypted_message")
    # Convert encrypted message from hex to bytes
    ciphertext = bytes.fromhex(encrypted_message)

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode("utf-8")  # Return as a UTF-8 decoded string

# 5. Decomprim mesajul 
def decompress_message(compressed_message: str) -> dict:
    compressed_data = base64.b64decode(compressed_message)

    # Decompress using zlib
    decompressed_bytes = zlib.decompress(compressed_data)

    # Convert bytes back to JSON string and then to dictionary
    return json.loads(decompressed_bytes.decode('utf-8'))

# 6. Calculez hash ul mesajului
def calculate_hash_message(message):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message)
    return digest.finalize()

def get_leading_two_octets(hash_result: bytes) -> bytes:
    return hash_result[:2]

# 6.1 Compar prima data primii 2 octeti ai mesajului cu primii 2 octeti primiti
# daca sunt egali trec la urmatoarea verificare altfel nu mai are rost sa continui
def first_verification(message):
    mesaj=message.get("message_part")
    semnatura=message.get("signature_part")
    
    hash_mesaj=calculate_hash_message(mesaj)
    
    recalculated_leading_two_octets = get_leading_two_octets(hash_mesaj)
    received_leading_two_octets = bytes.fromhex(semnatura.get("leading_octets_of_digest"))
    
    if recalculated_leading_two_octets == received_leading_two_octets:
        print("First verification passed: Leading two octets match.")
        return True
    else:
        print("First verification failed: Leading two octets do not match.")
        return False

# 7. Verific daca semnatura este valida
def verify_message(message, rsa_public_key):
    mesaj=message.get("message_part")
    
    semnatura=message.get("signature_part")
    signature_to_verify=semnatura.get("signature")
    
    try:
        
        hash_mesaj=calculate_hash_message(mesaj)
        # Verify the signature
        rsa_public_key.verify(
            signature_to_verify,
            hash_mesaj,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True  # Signature is valid
    except Exception:
        return False  # Signature is invalid
    

    