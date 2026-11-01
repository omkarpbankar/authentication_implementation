"""A service that only talks to clients holding a certificate from our private CA.

Run:  uv run python -m apps.mtls_lab.server
"""

import ssl

import uvicorn
from fastapi import FastAPI

from apps.mtls_lab.make_certs import OUT

app = FastAPI(title="mTLS lab")


@app.get("/internal/balance")
def balance() -> dict[str, int]:
    # If this code runs at all, the TLS handshake has already proved the client's certificate.
    return {"balance": 1000}


def main() -> None:
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8443,
        log_level="warning",
        ssl_keyfile=str(OUT / "server.key"),
        ssl_certfile=str(OUT / "server.pem"),
        ssl_ca_certs=str(OUT / "ca.pem"),
        # This one setting is what makes it mutual: the client must prove itself too.
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()
