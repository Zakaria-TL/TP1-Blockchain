import asyncio
import sys
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding

PORTS = {
    "alice": 5001,
    "bob": 5002,
    "carol": 5003,
    "dave": 5004
}


class ConsortiumNode:
    def __init__(self, name):
        self.name = name.lower()
        self.port = PORTS[self.name]
        self.load_keys_and_certs()

    def load_keys_and_certs(self):
        with open(f"certs/{self.name}_key.pem", "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)

        with open(f"certs/{self.name}_cert.pem", "rb") as f:
            self.cert = x509.load_pem_x509_certificate(f.read())
            self.public_key = self.cert.public_key()

        with open("certs/ca_cert.pem", "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())



    def verify_peer_certificate(self, peer_cert_bytes):
        """التحقق من الشهادة ومن عدم إبطالها (CRL Check)"""
        try:
            peer_cert = x509.load_pem_x509_certificate(peer_cert_bytes)
            ca_pub_key = self.ca_cert.public_key()

            # 1. التحقق من التوقيع والصلاحية
            ca_pub_key.verify(
                peer_cert.signature,
                peer_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                peer_cert.signature_hash_algorithm,
            )

            # 2. فحص قائمة الإبطال (CRL) إن وجدت (Bonus)
            if os.path.exists("certs/crl.pem"):
                with open("certs/crl.pem", "rb") as f:
                    crl = x509.load_pem_crl(f.read())
                    revoked = crl.get_revoked_certificate_by_serial_number(peer_cert.serial_number)
                    if revoked is not None:
                        print(f"[{self.name.capitalize()}] REJECTED: Certificate has been REVOKED!")
                        return None

            print(f"[{self.name.capitalize()}] Verified peer certificate successfully!")
            return peer_cert.public_key()
        except Exception as e:
            print(f"[{self.name.capitalize()}] Certificate verification failed: {e}")
            return None

    # --- الخطوة 5: التشفير المتماثل وفحص التلاعب ---
    @staticmethod
    def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # إرفاق الـ nonce مع النص المشفر

    @staticmethod
    def aes_decrypt(key: bytes, payload: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = payload[:12]
        ciphertext = payload[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    # --- الخطوة 6: التشفير الهجين (ECDH + HKDF + AES-GCM) ---
    def generate_ecdh_keypair(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key, private_key.public_key()

    @staticmethod
    def derive_aes_key(shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit AES key
            salt=None,
            info=b"consortium session key",
        ).derive(shared_secret)

    async def handle_connection(self, reader, writer):
        writer.write(self.cert.public_bytes(Encoding.PEM))
        await writer.drain()

        mode_bytes = await reader.read(4)
        mode = mode_bytes.decode()

        if mode == "ASYM":
            data = await reader.read(4096)
            decrypted = self.private_key.decrypt(
                data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"[{self.name.capitalize()}] [ASYMMETRIC] Received: {decrypted.decode()}")

        elif mode == "HYBD":
            # استقبال المفتاح العام المؤقت للطرف الآخر (ECDH)
            peer_ec_pub_bytes = await reader.read(100)
            peer_ec_pub = load_pem_public_key(peer_ec_pub_bytes)

            # توليد المفتاح الخاص بنا لحساب السر المشترك
            ephemeral_priv, ephemeral_pub = self.generate_ecdh_keypair()
            writer.write(ephemeral_pub.public_bytes(Encoding.PEM, x509.serialization.PublicFormat.SubjectPublicKeyInfo))
            await writer.drain()

            shared_secret = ephemeral_priv.exchange(ec.ECDH(), peer_ec_pub)
            session_key = self.derive_aes_key(shared_secret)

            payload = await reader.read(8192)
            plaintext = self.aes_decrypt(session_key, payload)
            print(f"[{self.name.capitalize()}] [HYBRID] Decrypted: {plaintext.decode()}")

        writer.close()
        await writer.wait_closed()

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, '127.0.0.1', self.port)
        print(f"[{self.name.capitalize()}] Listening on port {self.port}...")
        async with server:
            await server.serve_forever()

    async def send_asymmetric_message(self, peer_name, message):
        """إرسال رسالة مشفرة غير متماثلة لعقدة أخرى"""
        peer_name = peer_name.lower()
        peer_port = PORTS[peer_name]

        print(f"[{self.name.capitalize()}] Connecting to {peer_name.capitalize()} on port {peer_port}...")
        reader, writer = await asyncio.open_connection('127.0.0.1', peer_port)

        # استقبال شهادة الطرف الآخر والتحقق منها
        peer_cert_bytes = await reader.read(4096)
        peer_pub_key = self.verify_peer_certificate(peer_cert_bytes)

        if not peer_pub_key:
            print(f"[{self.name.capitalize()}] Aborting connection due to invalid certificate.")
            writer.close()
            return

        # إخبار السيرفر أن الوضع غير متماثل
        writer.write(b"ASYM")
        await writer.drain()

        # تشفير الرسالة باستخدام المفتاح العام للطرف الآخر (RSA-OAEP)
        ciphertext = peer_pub_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        writer.write(ciphertext)
        await writer.drain()
        print(f"[{self.name.capitalize()}] Sent asymmetric message to {peer_name.capitalize()}.")
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python node.py [alice|bob|carol|dave]")
        sys.exit(1)
        node_name = sys.argv[1]
    node = ConsortiumNode(sys.argv[1])
    try:
        asyncio.run(node.start_server())
    except KeyboardInterrupt:
        print(f"\n[{sys.argv[1].capitalize()}] Shutting down.")