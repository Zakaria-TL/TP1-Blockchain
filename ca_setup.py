import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
import datetime

# 1. إنشاء مجلد لحفظ الشهادات والمفاتيح
os.makedirs("certs", exist_ok=True)

print("[*] Generating CA Private Key and Certificate...")

# توليد المفتاح الخاص للـ CA
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# بيانات جهة الإصدار (CA)
ca_subject = ca_issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Consortium CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Consortium Root CA"),
])

# إنشاء شهادة ذاتية التوقيع للـ CA (صالحة لمدة سنة)
ca_certificate = x509.CertificateBuilder().subject_name(
    ca_subject
).issuer_name(
    ca_issuer
).public_key(
    ca_private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(ca_private_key, hashes.SHA256())

# حفظ شهادة ومفتاح الـ CA
with open("certs/ca_cert.pem", "wb") as f:
    f.write(ca_certificate.public_bytes(Encoding.PEM))

with open("certs/ca_key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    ))

print("[+] CA created successfully!")
crl = x509.CertificateRevocationListBuilder().issuer_name(
    ca_certificate.subject
).last_update(
    datetime.datetime.utcnow()
).next_update(
    datetime.datetime.utcnow() + datetime.timedelta(days=7)
).sign(ca_private_key, hashes.SHA256())

with open("certs/crl.pem", "wb") as f:
    f.write(crl.public_bytes(Encoding.PEM))
# 2. إنشاء المفاتيح والشهادات للعقد الأربع
nodes = ["Alice", "Bob", "Carol", "Dave"]

for node in nodes:
    print(f"[*] Generating keys and certificate for {node}...")

    # توليد مفتاح خاص للعقدة
    node_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # إنشاء طلب توقيع شهادة (CSR)
    node_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Consortium Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, node),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        node_subject
    ).sign(node_private_key, hashes.SHA256())

    # توقيع الشهادة بواسطة الـ CA
    node_certificate = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=30)  # صالحة لمدة 30 يوماً
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    # حفظ مفتاح وشهادة العقدة في المجلد
    node_lower = node.lower()
    with open(f"certs/{node_lower}_key.pem", "wb") as f:
        f.write(node_private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    with open(f"certs/{node_lower}_cert.pem", "wb") as f:
        f.write(node_certificate.public_bytes(Encoding.PEM))

print("[+] All node certificates and keys generated successfully inside 'certs/' folder!")