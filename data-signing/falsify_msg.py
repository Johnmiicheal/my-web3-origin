from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

message = b'Mike Ross is a fraud'
signature = b'Fake Signature'

with open("mikekey.pub", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend())

public_key.verify(
        signature, 
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
