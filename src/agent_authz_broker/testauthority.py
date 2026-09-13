"""A deterministic test authority that mints real, really-signed tokens — including bad ones.

**This is not an authorization server and must never be mistaken for one.** It has no clients, no
consent, no discovery, no refresh, and no story about who is allowed to ask it for what. It exists
so the adversarial suite and the public demonstration can present tokens that are genuinely valid
except in the one way each test is about — and so *wrong-audience* means a real Ed25519 signature
over a different `aud`, not a fixture with a flag set on it.

Keys are Ed25519, generated in memory per process, never written to disk and never committed. The
public demonstration signs on the server; nothing private reaches a browser.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt import PyJWKSet
from jwt.utils import base64url_encode

__all__ = ["Flaw", "TestAuthority"]

#: The ways a token can be wrong that the suite needs to present. Each is produced by real signing,
#: not by a fixture that claims to be broken.
Flaw = Literal["expired", "bad_signature", "unknown_issuer", "missing_scope"]


class TestAuthority:
    """Mints tokens for the lab. One instance, one key, one issuer.

    Deterministic in identity — same issuer, same `kid` — but the signing key is fresh per process,
    so nothing here is a credential and there is nothing to leak.
    """

    def __init__(
        self, issuer: str = "https://authority.demo.invalid", key_id: str = "demo-1"
    ) -> None:
        self.issuer = issuer
        self.key_id = key_id
        self._key = Ed25519PrivateKey.generate()
        #: A second key the server does not trust, for forging a signature that is real but wrong.
        self._foreign_key = Ed25519PrivateKey.generate()

    # ------------------------------------------------------------------ the key set the server read

    def jwks(self) -> PyJWKSet:
        """The public key set, in the shape a resource server would fetch over HTTPS."""
        public = self._key.public_key()
        raw = public.public_bytes_raw()
        return PyJWKSet.from_dict(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": self.key_id,
                        "alg": "EdDSA",
                        "use": "sig",
                        "x": base64url_encode(raw).decode(),
                    }
                ]
            }
        )

    # ------------------------------------------------------------------------------------ minting

    def _sign(self, payload: dict[str, Any], *, key: Ed25519PrivateKey | None = None) -> str:
        return jwt.encode(
            payload,
            key or self._key,  # type: ignore[arg-type]
            algorithm="EdDSA",
            headers={"kid": self.key_id},
        )

    def _base(
        self,
        *,
        subject: str,
        audience: str,
        scopes: list[str],
        lifetime: int = 300,
        issued_at: int | None = None,
    ) -> dict[str, Any]:
        now = issued_at if issued_at is not None else int(time.time())
        return {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + lifetime,
            "jti": uuid.uuid4().hex,
            "scope": " ".join(sorted(scopes)),
        }

    def mint(
        self,
        *,
        subject: str,
        audience: str,
        scopes: list[str],
        lifetime: int = 300,
    ) -> str:
        """A straightforward token issued directly to its subject."""
        return self._sign(
            self._base(subject=subject, audience=audience, scopes=scopes, lifetime=lifetime)
        )

    def mint_delegated(
        self,
        *,
        chain: list[tuple[str, list[str]]],
        subject: str,
        audience: str,
        scopes: list[str],
        lifetime: int = 300,
    ) -> str:
        """A token carrying an RFC 8693 ``act`` chain.

        ``chain`` is root-first, the way a reader thinks about it; the nesting is built inside out
        here so that no caller has to reason about which direction ``act`` nests.

        The leaf's ``scope`` is whatever the caller asks for — including more than the chain grants.
        That is the entire point: the amplification test needs a token that *claims* too much,
        signed properly, so the refusal comes from the attenuation rule and not from a malformed
        input.
        """
        payload = self._base(subject=subject, audience=audience, scopes=scopes, lifetime=lifetime)
        actor: dict[str, Any] | None = None
        for link_subject, link_scopes in chain:
            node: dict[str, Any] = {"sub": link_subject, "scope": " ".join(sorted(link_scopes))}
            if actor is not None:
                node["act"] = actor
            actor = node
        if actor is not None:
            payload["act"] = actor
        return self._sign(payload)

    def mint_flawed(
        self,
        flaw: Flaw,
        *,
        subject: str,
        audience: str,
        scopes: list[str],
    ) -> str:
        """A token broken in exactly one declared way, and correct in every other."""
        if flaw == "expired":
            past = int(time.time()) - 7200
            return self._sign(
                self._base(
                    subject=subject,
                    audience=audience,
                    scopes=scopes,
                    lifetime=3600,
                    issued_at=past,
                )
            )
        if flaw == "bad_signature":
            # Signed with a real Ed25519 key the server has never heard of, under the trusted `kid`.
            # A tampered payload would also fail, but this is the sharper case: the cryptography is
            # impeccable and the key is simply not ours.
            return self._sign(
                self._base(subject=subject, audience=audience, scopes=scopes),
                key=self._foreign_key,
            )
        if flaw == "unknown_issuer":
            payload = self._base(subject=subject, audience=audience, scopes=scopes)
            payload["iss"] = "https://attacker.invalid"
            return self._sign(payload)
        if flaw == "missing_scope":
            without = [scope for scope in scopes if scope != "credit:issue"]
            return self._sign(self._base(subject=subject, audience=audience, scopes=without))
        raise ValueError(f"unknown flaw: {flaw}")
