#!/usr/bin/env python3
from typing import Any, Dict

from authlib.jose import jwk, jwt


def create_RS256_jwt(payload: Dict[str, Any], key: str) -> str:
    if key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        key = jwk.dumps(key, kty="RSA")
    if key.startswith("-----BEGIN PRIVATE KEY-----"):
        key = jwk.dumps(key, kty="RSA")

    header = {"alg": "RS256"}
    result: bytes = jwt.encode(header, payload, key)
    return result.decode("ascii")


def create_HS256_jwt(payload: Dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256"}
    result: bytes = jwt.encode(header, payload, secret)
    return result.decode("ascii")


def example_rsa() -> None:
    payload = {"sub": "user1", "aud": ["audience"]}

    key = "\n".join(
        [
            "-----BEGIN PRIVATE KEY-----",
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKZ51yIlJkxrY4U9",
            "5r87tr7gmPPDEdJVo7FIxgqJzTZ2C/PnCfWz0L+vNepyotBMf4aAb8msMPq2tCLf",
            "vb3SD8WJ6ZLV5VRfJz40WLA6pg6D1bQBN3SF6Nr1YistbJZmfQcwk9uSoHcE4yTj",
            "bWzRWijCtbbUmvh9QwF8PFc0fZJ1AgMBAAECgYBQddTnuOLQzpp0HJ340WiayrzC",
            "HAbyDNgn6E9naoDXkKhoQsNKkJUVAB7j6HIOkNqV7F+bLnEhy8o2jMMNCoj6HadX",
            "i5Urj0u1bxSHEDVCAFwo83zuy77Gf3nycofd8/PwJjMQl9kQ9z35Gb8CJe0y6EB2",
            "DxE8EbEkro80z4WKAQJBANtzyUvcW+Yq0nt/vKePMri0QFnwbSeRiBHLBZjpBxfd",
            "KVA+KB86JZnvL7co8ngOAmPTdUvOELa1+ovlNlOY3vUCQQDCM3CYsr/xV5z1tsVr",
            "gCqa3wntLBjUE4eAWM9v+vf6yjdLnVedYXp21YiyjOkQ2MuvnvAUMJKRGCIGOC3c",
            "SrWBAkEA050HUtue0oggh25ZoMn5AxrtosywtSMkruOy9gxfBqgBGpuVXOdZMuLu",
            "hBQ8G4CG1XQm+34tp8I7Y4MXq+0RsQJAYa4GAIhIS1hKNr1L55p705JEJ+t6QZHh",
            "IgmJrUWK3bZAwePOYfbZ5lPZghWmVTb2nMtQ7pbP4fNFieNQDfH2AQJBAMdc/saT",
            "lAlfA2po0IC/IpqNw2DJk/Ky7QShDJg8mp9QxoKwRy4sUPCOglcjVyE8CTaaar7E",
            "ZV3OjK9+FXn8Mkw=",
            "-----END PRIVATE KEY-----",
        ]
    )

    print(create_RS256_jwt(payload, key))


def example_hsa() -> None:
    payload = {"sub": "user1", "aud": ["audience"]}
    secret = "MyVeryPrivateSecret"
    print(create_HS256_jwt(payload, secret))


if __name__ == "__main__":
    example_rsa()
