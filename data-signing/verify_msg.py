from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

#CONFIGURATION

# Generate private key
#private_key = rsa.generate_private_key(
#   public_exponent=65537,
#   key_size=2048,
#   backend=default_backend()
#)


# Message validation execution: By public key holders
public_key.verify(
        signature,
        message, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
