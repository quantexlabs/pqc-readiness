"""Generate RSA-2048 key pair and self-signed certificate for tests."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqc-readiness-test")])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(tz=UTC))
    .not_valid_after(datetime.now(tz=UTC) + timedelta(days=365))
    .sign(key, hashes.SHA256())
)
pem = cert.public_bytes(serialization.Encoding.PEM)
Path = __import__("pathlib").Path
out = Path(__file__).resolve().parent.parent / "certs" / "rsa2048.pem"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(pem)
print(out)
