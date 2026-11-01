"""Create a tiny private certificate authority, with server and client certificates.

Run:  uv run python -m apps.mtls_lab.make_certs
Files go in apps/mtls_lab/.certs/, which Git ignores.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).parent / ".certs"
ONE_DAY = datetime.timedelta(days=1)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def write(prefix: str, key, cert: x509.Certificate) -> None:
    (OUT / f"{prefix}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (OUT / f"{prefix}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca(common_name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - ONE_DAY)
        .not_valid_after(now + 30 * ONE_DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(common_name: str, ca_key, ca_cert, usage, sans=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - ONE_DAY)
        .not_valid_after(now + 7 * ONE_DAY)  # Short-lived, as real service certificates are.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def main() -> None:
    OUT.mkdir(exist_ok=True)
    ca_key, ca_cert = make_ca("Course Private CA")
    write("ca", ca_key, ca_cert)

    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    server_key, server_cert = make_leaf(
        "localhost", ca_key, ca_cert, ExtendedKeyUsageOID.SERVER_AUTH, sans
    )
    write("server", server_key, server_cert)

    client_key, client_cert = make_leaf(
        "billing-service", ca_key, ca_cert, ExtendedKeyUsageOID.CLIENT_AUTH
    )
    write("client", client_key, client_cert)

    # A certificate from a different CA, which the server must refuse.
    other_key, other_cert = make_ca("Attacker CA")
    rogue_key, rogue_cert = make_leaf(
        "billing-service", other_key, other_cert, ExtendedKeyUsageOID.CLIENT_AUTH
    )
    write("rogue", rogue_key, rogue_cert)
    print(f"Certificates written to {OUT}")


if __name__ == "__main__":
    main()
