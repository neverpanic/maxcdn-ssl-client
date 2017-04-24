"""
Cryptography functionality dealing with certificates and their keys
"""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ExtensionOID

def load_privkey(stream):
    """
    Load and decode a PEM-encoded private key from the given bytestream and
    return an object representing this key.

    :param bytes stream: The PEM byte stream
    :rtype object: An object representing the private key
    """
    return load_pem_private_key(stream, password=None, backend=default_backend())

def load_x509(stream):
    """
    Load and decode a PEM-encoded X.509 certificate and return an object
    representing the certificate.

    :param bytes stream: The PEM byte stream
    :rtype object: An object representing the X.509 certificate
    """
    return load_pem_x509_certificate(stream, default_backend())

def key_matches_x509_crt(key, crt):
    """
    Verify that the public key derived from the given private key matches the
    private key in the given X.509 certificate.

    :param object key: A private key object created using load_privkey()
    :param object crt: An X.509 certificate object created using load_x509()
    :rtype bool: True, iff the key matches the certificate
    """
    return crt.public_key().public_numbers() == key.public_key().public_numbers()

def get_x509_cn(crt):
    """
    Obtain the CommonName (CN) field from a given X.509 certificate object.

    :param object crt: An X.509 certificate object created using load_x509()
    :rtype str: The X.509 common name field of the certificate, or None if
                there was none.
    """
    common_names = crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) <= 0:
        return None
    return common_names[0].value

def get_x509_sans(crt):
    """
    Obtain the SubjectAltName (SAN) certificate extension field form a given
    X.509 certificate object.

    :param object crt: An X.509 certificate object created using load_x509()
    :rtype list: A list of Subject Alternative Names
    """
    san_ext = crt.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    # Get the DNSName entries from the SAN extension
    return san_ext.value.get_values_for_type(x509.DNSName)

def x509_is_currently_valid(crt):
    """
    Check whether the notBefore and notAfter fields of the given X.509
    certificate are before and after the current date, respectively.

    :param object crt: An X.509 certificate object created using load_x509()
    :rtype bool: True, iff the certificate is currently valid
    """
    now = datetime.utcnow()
    if now < crt.not_valid_before:
        return False
    if now > crt.not_valid_after:
        return False
    return True
