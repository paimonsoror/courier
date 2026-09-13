"""Read OAuth client credentials that Courier delivered to Vault.

Courier stores each client at::

    kv/teams/<team>/oauth-clients/<team>-<name>

and only members of the IdP group ``<team>`` can read it. This module logs in
to Vault with *your* identity, reads the entry, checks it is ready, and returns
a typed object whose ``repr`` never shows the secret.

Log-in methods (``COURIER_VAULT_AUTH``), matching Courier's Vault setup:

``token``
    A Vault token you already have, e.g. after ``vault login -method=oidc``.
    Read from ``VAULT_TOKEN`` or ``~/.vault-token``. For people.
``jwt``
    A JWT issued by the identity provider to a workload, from ``COURIER_JWT``
    or the file named by ``COURIER_JWT_FILE``. Vault role ``machine`` on ``jwt/``.
``kubernetes``
    The pod's service account token. Vault role from ``VAULT_ROLE``.

Command line::

    python courier_credentials.py team-bravo report-exporter
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

import hvac
import hvac.exceptions

DEFAULT_SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class CredentialsNotReady(RuntimeError):
    """The entry exists but Courier has not finished delivering it."""


@dataclasses.dataclass(frozen=True)
class OAuthClientCredentials:
    """One Courier-delivered client. ``client_secret`` is excluded from repr."""

    path: str
    client_id: str
    client_type: str
    client_secret: str | None = dataclasses.field(repr=False)
    grant_types: tuple[str, ...]
    scopes: tuple[str, ...]
    issuer: str
    token_endpoint: str
    authorization_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str
    owner_group: str


def vault_client(
    addr: str | None = None,
    *,
    method: str | None = None,
    role: str | None = None,
    mount: str | None = None,
    jwt: str | None = None,
    namespace: str | None = None,
) -> hvac.Client:
    """Return an authenticated Vault client using the chosen log-in method."""
    addr = addr or os.environ.get("VAULT_ADDR")
    if not addr:
        raise ValueError("set VAULT_ADDR (for example https://vault.sororlab.dev)")
    method = method or os.environ.get("COURIER_VAULT_AUTH", "token")
    client = hvac.Client(url=addr, namespace=namespace or os.environ.get("VAULT_NAMESPACE"))

    if method == "token":
        token = os.environ.get("VAULT_TOKEN")
        token_file = pathlib.Path.home() / ".vault-token"
        if not token and token_file.exists():
            token = token_file.read_text().strip()
        if not token:
            raise PermissionError("no Vault token: run `vault login -method=oidc` or set VAULT_TOKEN")
        client.token = token
    elif method == "jwt":
        jwt = jwt or os.environ.get("COURIER_JWT")
        if not jwt and os.environ.get("COURIER_JWT_FILE"):
            jwt = pathlib.Path(os.environ["COURIER_JWT_FILE"]).read_text().strip()
        if not jwt:
            raise PermissionError("no JWT: set COURIER_JWT or COURIER_JWT_FILE")
        client.auth.jwt.jwt_login(role=role or os.environ.get("VAULT_ROLE", "machine"), jwt=jwt, path=mount or "jwt")
    elif method == "kubernetes":
        sa_jwt = pathlib.Path(os.environ.get("COURIER_SA_TOKEN_FILE", DEFAULT_SA_TOKEN)).read_text().strip()
        vault_role = role or os.environ.get("VAULT_ROLE")
        if not vault_role:
            raise ValueError("set VAULT_ROLE to the team's Kubernetes auth role")
        client.auth.kubernetes.login(role=vault_role, jwt=sa_jwt, mount_point=mount or "kubernetes")
    else:
        raise ValueError(f"unknown COURIER_VAULT_AUTH {method!r}: use token, jwt or kubernetes")

    if not client.is_authenticated():
        raise PermissionError("Vault did not accept the credentials")
    return client


def read_credentials(client: hvac.Client, team: str, name: str, *, kv_mount: str = "kv") -> OAuthClientCredentials:
    """Read and check the credentials Courier delivered for ``<team>/<name>``."""
    rel = f"teams/{team}/oauth-clients/{team}-{name}"
    full = f"{kv_mount}/{rel}"
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=rel, mount_point=kv_mount, raise_on_deleted_version=True
        )
    except hvac.exceptions.Forbidden as err:
        raise PermissionError(f"not allowed to read {full}: is this identity in IdP group {team!r}?") from err
    except hvac.exceptions.InvalidPath as err:
        raise LookupError(f"nothing at {full}: is the request merged and Ready?") from err

    data = response["data"]["data"]
    if data.get("state") != "active":
        raise CredentialsNotReady(f"{full} is {data.get('state')!r}; wait for the OAuthClient to be Ready")

    return OAuthClientCredentials(
        path=full,
        client_id=data["client_id"],
        client_type=data.get("client_type", ""),
        client_secret=data.get("client_secret"),
        grant_types=tuple(data.get("grant_types", "").split()),
        scopes=tuple(data.get("scopes", "").split()),
        issuer=data.get("issuer", ""),
        token_endpoint=data.get("token_endpoint", ""),
        authorization_endpoint=data.get("authorization_endpoint", ""),
        jwks_uri=data.get("jwks_uri", ""),
        userinfo_endpoint=data.get("userinfo_endpoint", ""),
        owner_group=data.get("owner_group", ""),
    )


def client_credentials_token(
    creds: OAuthClientCredentials, *, scope: str | None = None, extra: dict[str, str] | None = None
) -> dict:
    """Exchange confidential client credentials for an access token.

    ``extra`` carries provider-specific form fields. Authentik, for example,
    expects the service account's ``username`` and app-password ``password``
    alongside the client credentials.
    """
    if not creds.client_secret:
        raise ValueError(f"{creds.path} is a {creds.client_type} client without a secret")
    form = {
        "grant_type": "client_credentials",
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scope": scope or " ".join(creds.scopes),
        **(extra or {}),
    }
    request = urllib.request.Request(
        creds.token_endpoint,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as err:
        detail = json.loads(err.read() or b"{}").get("error", "")
        raise PermissionError(f"token endpoint returned HTTP {err.code} {detail}") from err


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show Courier-delivered credentials (secret redacted).")
    parser.add_argument("team")
    parser.add_argument("name")
    parser.add_argument("--kv-mount", default="kv")
    args = parser.parse_args(argv)

    try:
        creds = read_credentials(vault_client(), args.team, args.name, kv_mount=args.kv_mount)
    except (PermissionError, LookupError, CredentialsNotReady, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    print(creds)
    secret = "absent (public client)" if not creds.client_secret else f"present ({len(creds.client_secret)} chars)"
    print(f"client_secret: {secret}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
