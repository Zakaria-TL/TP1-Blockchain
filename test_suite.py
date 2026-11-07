import time
import os
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from node import ConsortiumNode


def test_step5_symmetric_tampering():
    print("\n--- [Step 5] Symmetric Encryption (AES-256-GCM) & Tampering Test ---")
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    message = b"Blockchain Consortium Sensitive Data Payload"

    # التشفير
    ciphertext = aesgcm.encrypt(nonce, message, None)
    print("[+] Message encrypted successfully.")

    # 1. التفكيك العادي
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    print(f"[+] Normal Decryption Result: {decrypted.decode()}")

    # 2. التلاعب بالبيانات (تغيير البايت الأول)
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip bits

    print("[*] Attempting decryption on tampered ciphertext...")
    try:
        aesgcm.decrypt(nonce, bytes(tampered_ciphertext), None)
        print("[-] ERROR: Tampering was NOT detected!")
    except Exception as e:
        print(f"[+] SUCCESS: Tampering detected! Decryption failed with error: {type(e).__name__}")


async def test_step6_hybrid_exchange(sender_name, receiver_name, message):
    print(f"\n--- [Step 6] Hybrid Encryption Exchange ({sender_name} -> {receiver_name}) ---")
    sender = ConsortiumNode(sender_name)
    receiver_port = sender.port if receiver_name == sender_name else sender.port  # Target port
    from node import PORTS
    target_port = PORTS[receiver_name.lower()]

    reader, writer = await asyncio.open_connection('127.0.0.1', target_port)

    # 1. المصادقة عبر الشهادة
    peer_cert_bytes = await reader.read(4096)
    peer_pub_key = sender.verify_peer_certificate(peer_cert_bytes)
    if not peer_pub_key:
        print("Aborting.")
        return

    writer.write(b"HYBD")
    await writer.drain()

    # 2. تبادل مفاتيح ECDH
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub = ephemeral_priv.public_key()

    writer.write(ephemeral_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    await writer.drain()

    peer_ec_pub_bytes = await reader.read(4096)
    peer_ec_pub = load_pem_public_key(peer_ec_pub_bytes)

    # 3. حساب المفتاح المشترك عبر HKDF
    shared_secret = ephemeral_priv.exchange(ec.ECDH(), peer_ec_pub)
    session_key = ConsortiumNode.derive_aes_key(shared_secret)

    # 4. تشفير وإرسال الرسالة عبر AES-GCM
    payload = ConsortiumNode.aes_encrypt(session_key, message.encode())
    writer.write(payload)
    await writer.drain()
    print(f"[+] Hybrid encrypted message sent to {receiver_name}.")
    writer.close()
    await writer.wait_closed()


def test_step8_benchmark():
    print("\n--- [Step 8] Performance Benchmark: RSA-2048 vs AES-256 ---")
    sizes = {
        "1 KB": 1024,
        "1 MB": 1024 * 1024,
        "10 MB": 10 * 1024 * 1024
    }

    # توليد مفاتيح الاختبار
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_key.public_key()
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    print(f"| Size | Algorithm | Encrypt Time (s) | Decrypt Time (s) | Ciphertext Size |")
    print(f"|---|---|---|---|---|")

    for label, size in sizes.items():
        data = os.urandom(size)

        # 1. AES-256 Benchmark
        t0 = time.perf_counter()
        nonce = os.urandom(12)
        aes_cipher = nonce + aesgcm.encrypt(nonce, data, None)
        t_aes_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        aesgcm.decrypt(aes_cipher[:12], aes_cipher[12:], None)
        t_aes_dec = time.perf_counter() - t0

        print(f"| {label} | AES-256-GCM | {t_aes_enc:.6f}s | {t_aes_dec:.6f}s | {len(aes_cipher)} bytes |")

        # 2. RSA-2048 Benchmark
        # RSA لا يمكنه تشفير بيانات أكبر من حجم المفتاح (~214 بايت لـ 2048-bit مع OAEP)
        if size > 214:
            print(f"| {label} | RSA-2048-OAEP | N/A (Payload too large for RSA) | N/A | N/A |")
        else:
            t0 = time.perf_counter()
            rsa_cipher = rsa_pub.encrypt(data,
                                         padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                      label=None))
            t_rsa_enc = time.perf_counter() - t0

            t0 = time.perf_counter()
            rsa_key.decrypt(rsa_cipher,
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            t_rsa_dec = time.perf_counter() - t0

            print(f"| {label} | RSA-2048-OAEP | {t_rsa_enc:.6f}s | {t_rsa_dec:.6f}s | {len(rsa_cipher)} bytes |")


if __name__ == "__main__":
    # تشغيل اختبار المتماثل والتلاعب
    test_step5_symmetric_tampering()

    # تشغيل جدول المقارنة
    test_step8_benchmark()