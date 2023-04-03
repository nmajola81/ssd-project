from flask import jsonify
import json
from cryptography.fernet import Fernet

def encrypt_data_dict(datadict, enc_key):

    # Create a Fernet instance with the key
    fernet = Fernet(enc_key)

    # Convert the data to a JSON string
    json_data = json.dumps(datadict)

    # Encrypt the JSON string
    return fernet.encrypt(json_data.encode())

def decrypt_data(encrypted_data, dec_key):

    # Generate a Fernet key

    # Create a Fernet instance with the key
    fernet = Fernet(dec_key)

    decrypted_data = fernet.decrypt(encrypted_data)

    # Parse the JSON data
    json_data = json.loads(decrypted_data.decode())

    # Display the decrypted data
    return json_data