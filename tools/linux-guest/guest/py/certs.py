#!/usr/bin/env python3
"""X.509 helpers for the CCID tests, with python3-cryptography (a dependency of ykman).

usage:
  certs.py large OUT-PEM OUT-DER MIN MAX
      a self-signed P-256 certificate whose DER is MIN..MAX bytes, padded with
      subjectAltName DNS names; written as PEM and DER; prints the DER size
  certs.py verify PEM
      checks a self-signed certificate's signature with its own public key (a PIV
      `certificates generate` signs the certificate on the device); prints the subject,
      the signature algorithm and "signature valid", exit 1 if it is not

A PIV certificate object holds at most 3052 bytes of certificate (lk-piv's
MAX_CERT_VALUE, the published YubiKey limit), so MAX should stay at or below that.
"""

import datetime
import sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


def large(out_pem, out_der, low, high):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localkey large certificate")])
    count = 1
    while True:
        names = [x509.DNSName("host%04d.localkey.example" % i) for i in range(count)]
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0x10CA1)
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2036, 1, 1))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        if len(der) >= low:
            break
        # About 28 bytes per name; step close to the target, then one at a time.
        count += max(1, (low - len(der)) // 32)
    if len(der) > high:
        print("certificate of %d bytes is over %d" % (len(der), high))
        return 1
    with open(out_pem, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(out_der, "wb") as f:
        f.write(der)
    print("der=%d names=%d" % (len(der), count))
    return 0


def verify(path):
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    public = cert.public_key()
    print("subject=%s" % cert.subject.rfc4514_string())
    oid = cert.signature_algorithm_oid
    print("signature_algorithm=%s" % getattr(oid, "_name", oid.dotted_string))
    try:
        if isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public, rsa.RSAPublicKey):
            public.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            print("unsupported key type %s" % type(public).__name__)
            return 1
    except InvalidSignature:
        print("signature INVALID")
        return 1
    print("signature valid")
    return 0


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "large":
        return large(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        return verify(sys.argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
