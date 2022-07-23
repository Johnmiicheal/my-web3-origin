from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

def fetch_public_key(user):
    with open(user.decode('ascii') + "key.pub", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
        return public_key

# Messages coming from user
message = b'Mike Ross went to Harvard'

# Signature coming from user, this is very specific to public key
signature= b's@\xa8\x0bV\x90\x00\xb705x\x11>\xf3\x92@\xc0\xc8w\x05\x02\xcc\xd4\xb6_$5%`\xb9\xe7\x8e\t1\xe9\x8d\xdekK\xe7W\'\x1ceE\xfe\xe90\xf5\xe3Yx\xf9D\xe5V\xb4\xe1b\xad\xd9R"\xde`)\xce\xfau\xd1{\x14\xd8\xd6M\xc6\x96\xacy\xdbI\xfc\'\xb7<y\x0b\xab\\\x12E\x81T\x10\xf5%\x93fv6\x91jdL\xa0|\xe1\xdcm\x16\xe6\x89-\xba+kLW\xe6n\x011\'1\x08\x1e\xa7\xe8'

user = message.split()[0].lower()
# fetch public key from Mike
public_key = fetch_public_key(user)
# verify the message
public_key.verify(
        signature, 
        message, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

