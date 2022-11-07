#Julien Voeung PROJET 2

#import des libs disponibles pour le choix des algorithmes
from cryptography.hazmat.primitives.asymmetric import rsa

#imports des libs pour crée un CA
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

print("Bienvenue, vous êtes sur un script de génération de clé et certificat")
print("Veuillez faire votre choix en indiquant le chiffre correspondant ")
print("Fonction de hashage : ")

print("1. SHA 256")
print("2. SHA3 256")
print("3. SHA1")
print("4. MD5")
print("5. BLAKE2b")

#génération d'une clé publique et privée RSA
private_key = rsa.generate_private_key(
public_exponent=65537,
key_size=2048,)

public_key = private_key.public_key()

# Write our key to disk for safe keeping
with open("private_key_request.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))


#choix du hash
choix = input()
if(choix == 1):
    
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RequestJulienEsiea"),
    ])
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())


    with open("request.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

elif(choix == 2):

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RequestJulienEsiea"),
    ])
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA3_256())


    with open("request.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

elif(choix == 3):

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RequestJulienEsiea"),
    ])
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA1())


    with open("request.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

elif(choix == 4):

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RequestJulienEsiea"),
    ])
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.MD5())


    with open("request.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

elif(choix == 5):

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RequestJulienEsiea"),
    ])
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.BLAKE2b())


    with open("request.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))






