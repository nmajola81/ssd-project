'''Module with helper functions for encrypting and descrypting data

Functions:
    encrypt_data_dict - Takes a data dict and encrypts it
    decrypt_data - Takes encrypted data structure and decrypts it

'''

from flask import jsonify
import json
from cryptography.fernet import Fernet

def encrypt_data_dict(datadict, enc_key):

    '''
    Takes a data dict and encrypts it

    Args:
        datadict: Dict to eb encrypted
        enc_key: Fernet encryption key

    Returns: Encrypted data

    '''

    # Create a Fernet instance with the key
    fernet = Fernet(enc_key)

    # Convert the data to a JSON string
    json_data = json.dumps(datadict)

    # Encrypt the JSON string
    return fernet.encrypt(json_data.encode())

def decrypt_data(encrypted_data, dec_key):

    '''
    Takes encrypted data structure and decrypts it

    Args:
        encrypted_data: Data that has been encrypted (retrieved from the DB)
        dec_key: Fernet encryption key

    Returns: Unencrypted data

    '''

    # Generate a Fernet key

    # Create a Fernet instance with the key
    fernet = Fernet(dec_key)

    decrypted_data = fernet.decrypt(encrypted_data)

    # Parse the JSON data
    json_data = json.loads(decrypted_data.decode())

    # Display the decrypted data
    return json_data