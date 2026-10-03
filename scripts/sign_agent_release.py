from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import boto3


def release_message(version: str, os_info: str, sha256_hex: str) -> bytes:
    return f"aegis-agent-release-v1\n{version}\n{os_info}\n{sha256_hex.lower()}".encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign an Aegis agent release with AWS KMS RSA-PSS.")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--os-info", required=True, choices=[
        "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64",
    ])
    parser.add_argument("--key-arn", required=True)
    parser.add_argument("--region", default="eu-central-1")
    args = parser.parse_args()

    if not args.artifact.is_file():
        parser.error("artifact path must be a regular file")
    if not args.key_arn.startswith(f"arn:aws:kms:{args.region}:"):
        parser.error("KMS key ARN must belong to the selected EU region")

    kms = boto3.client("kms", region_name=args.region)
    key_info = kms.get_public_key(KeyId=args.key_arn)
    if key_info["KeyUsage"] != "SIGN_VERIFY" or "RSASSA_PSS_SHA_256" not in key_info["SigningAlgorithms"]:
        parser.error("KMS key must support SIGN_VERIFY with RSASSA_PSS_SHA_256")

    digest = sha256_file(args.artifact)
    signature = kms.sign(
        KeyId=args.key_arn,
        Message=release_message(args.version, args.os_info, digest),
        MessageType="RAW",
        SigningAlgorithm="RSASSA_PSS_SHA_256",
    )["Signature"]
    print(json.dumps({
        "version": args.version,
        "os_info": args.os_info,
        "sha256": digest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "agent_public_key_b64": base64.b64encode(key_info["PublicKey"]).decode("ascii"),
        "kms_key_arn": args.key_arn,
        "region": args.region,
    }, separators=(",", ":")))


if __name__ == "__main__":
    main()
