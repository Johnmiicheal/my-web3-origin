from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


#CONFIGURATION
GENERATE_PRIVATE_KEY = False
DERIVE_PUB_KEY_FROM_PRIV_KEY = False
PRIVATE_KEY_FILE = "mikekey.pem"
PUBLIC_KEY_FILE = "mikekey.pub"
MESSAGE = b"Mike Ross went to Harvard"

# Generate private key
#private_key = rsa.generate_private_key(
#   public_exponent=65537,
#   key_size=2048,
#   backend=default_backend()
#)

if GENERATE_PRIVATE_KEY:
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
    )
else:
    # Load private key from pem file
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password= None,
                backend=default_backend()
            )
signature = private_key.sign(
        MESSAGE, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
    )

if DERIVE_PUB_KEY_FROM_PRIV_KEY: 
    # Getting public key from private key 
    public_key = private_key.puvlic_key()
else:
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


# Message validation execution: By public key holders
public_key.verify(
        signature,
        MESSAGE, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

print(signature)
