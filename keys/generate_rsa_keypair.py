from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair

    Returns:
        Tuple of (private_key, public_key) in PEM bytes
    """
    # Generate key with e = 65537
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Convert to PEM (no password protection because assignment requires committing it)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


if __name__ == "__main__":
    priv, pub = generate_rsa_keypair()

    # Save files exactly as required
    with open("student_private.pem", "wb") as f:
        f.write(priv)

    with open("student_public.pem", "wb") as f:
        f.write(pub)

    print("Generated student_private.pem and student_public.pem successfully!")
