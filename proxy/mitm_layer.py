import logging
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    from proxy import Proxy  # type: ignore
    from proxy.http.proxy import HttpProxyBasePlugin  # type: ignore
except Exception:  # pragma: no cover - proxy.py optional for demo
    HttpProxyBasePlugin = object  # type: ignore
    Proxy = None  # type: ignore


@dataclass
class CertificateBundle:
    """Paths to synthetic root CA certificate and key."""

    ca_cert_path: Path
    ca_key_path: Path
    generated_dir: Path


def generate_root_ca(common_name: str = "Synthetic ShadowAI CA") -> CertificateBundle:
    """Generate a self-signed CA certificate for synthetic MITM demos."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(x509.datetime.datetime.utcnow())
        .not_valid_after(x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )

    temp_dir = Path(tempfile.mkdtemp(prefix="shadowai-ca-"))
    ca_cert_path = temp_dir / "ca.crt"
    ca_key_path = temp_dir / "ca.key"

    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(ca_key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return CertificateBundle(
        ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, generated_dir=temp_dir
    )


def build_ssl_context(bundle: CertificateBundle) -> ssl.SSLContext:
    """Build an SSL context using the generated CA bundle."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(bundle.ca_cert_path), keyfile=str(bundle.ca_key_path))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SyntheticMITMPlugin(HttpProxyBasePlugin):  # pragma: no cover - requires proxy runtime
    """proxy.py plugin that logs TLS handshakes; redaction happens upstream."""

    def before_upstream_connection(self, request):
        """Log upstream connection attempts during TLS interception."""
        self.logger.info("TLS connect %s", request.host)
        return super().before_upstream_connection(request)


class MITMLayer:
    def __init__(self, bundle: CertificateBundle | None = None) -> None:
        """Create a MITM layer with a synthetic root CA bundle."""
        self.bundle = bundle or generate_root_ca()
        self.logger = logging.getLogger(__name__)

    def start(self, listen_addr: str = "0.0.0.0:8899") -> None:
        """Start proxy.py-based MITM proxy; lab-only."""
        if Proxy is None:
            raise RuntimeError("proxy.py not installed; install to enable live MITM.")
        host, port_str = listen_addr.split(":")
        port = int(port_str)
        ssl_ctx = build_ssl_context(self.bundle)
        # proxy.py will handle certificate presentation with provided CA.
        proxy = Proxy(  # type: ignore
            input_args=[
                "--hostname",
                host,
                "--port",
                str(port),
                "--plugins",
                "proxy.mitm_layer.SyntheticMITMPlugin",
                "--ca-key-file",
                str(self.bundle.ca_key_path),
                "--ca-cert-file",
                str(self.bundle.ca_cert_path),
            ],
            ssl_ctx=ssl_ctx,
        )
        self.logger.info("Starting MITM proxy on %s", listen_addr)
        proxy.run()

    def describe(self) -> str:
        """Human-readable description of current MITM configuration."""
        return f"Synthetic MITM with CA at {self.bundle.ca_cert_path}"
