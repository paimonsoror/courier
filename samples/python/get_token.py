"""Example: a machine-to-machine job that fetches its own credentials and a token.

    COURIER_VAULT_AUTH=kubernetes VAULT_ROLE=team-bravo \
    VAULT_ADDR=http://vault-active.vault.svc:8200 \
    AUTHENTIK_USERNAME=... AUTHENTIK_PASSWORD=... \
    python get_token.py team-bravo report-exporter

The job never has the secret in its configuration: it reads it from Vault at
start-up using its own identity, then uses it straight away.
"""

from __future__ import annotations

import os
import sys

from courier_credentials import client_credentials_token, read_credentials, vault_client


def main() -> int:
    team, name = sys.argv[1], sys.argv[2]
    creds = read_credentials(vault_client(), team, name)

    # Authentik's client_credentials grant also identifies the service account.
    extra = {}
    if os.environ.get("AUTHENTIK_USERNAME"):
        extra = {"username": os.environ["AUTHENTIK_USERNAME"], "password": os.environ["AUTHENTIK_PASSWORD"]}

    token = client_credentials_token(creds, extra=extra)
    print(f"client {creds.client_id} obtained a {token.get('token_type')} token, expires in {token.get('expires_in')}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
