from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import random
import string
import base64
import os

def generate_self_signed_cert_old():
    """
    Generate a self-signed X.509 certificate and return its PEM and private key as a string.
    """

    # Generate RSA key pair (2048 bits)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Certificate subject & issuer details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "BadZureGeneratedCert")
    ])

    # Certificate validity (1 year)
    cert = x509.CertificateBuilder().subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .sign(key, hashes.SHA256())

    # Convert to PEM format
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    return cert_pem, key_pem

def generate_certificate_and_key(app_name):
    """
    Generates a self-signed certificate and private key, and saves them to disk.
    Returns the file paths for Terraform to reference.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, app_name),
    ])

    # Certificate validity (1 year)
    cert = x509.CertificateBuilder().subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .sign(private_key, hashes.SHA256())


    # Generate a random file suffix to prevent name collisions
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    cert_filename = f"{app_name}-{random_suffix}.pem"
    key_filename = f"{app_name}-{random_suffix}.key"

    # Ensure the certs directory exists
    #os.makedirs("certs", exist_ok=True)

    # Save certificate
    with open("terraform/"+  cert_filename, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    # Save private key
    with open("terraform/"+ key_filename, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return cert_filename, key_filename