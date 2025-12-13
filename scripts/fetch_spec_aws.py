#!/usr/bin/env python3
"""Fetch OpenAPI spec from S3 using the AWS CLI and write to specs/payment-refund-api-openapi.yaml

Requirements:
- Read `AWS_SPEC_S3_URI` from environment (required)
- Use `aws s3 cp` (no boto3)
- Fail fast on missing env or download error
- Minimal, CI-safe, no secrets printed
"""
import os
import sys
import subprocess
from pathlib import Path

SPEC_DEST = Path(__file__).resolve().parents[1] / "specs" / "payment-refund-api-openapi.yaml"


def main():
    uri = os.getenv("AWS_SPEC_S3_URI")
    if not uri:
        print("FATAL: AWS_SPEC_S3_URI environment variable is not set.")
        sys.exit(1)

    # Ensure specs directory exists
    SPEC_DEST.parent.mkdir(parents=True, exist_ok=True)

    print(f"Starting download of OpenAPI spec from S3")
    try:
        # Call AWS CLI; let credentials be resolved by environment/instance profile
        completed = subprocess.run(
            ["aws", "s3", "cp", uri, str(SPEC_DEST)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(f"Successfully downloaded spec to: {SPEC_DEST}")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        # Do not print environment variables or secrets; surface a concise error
        stderr = (e.stderr or "").strip()
        print("FATAL: failed to download spec from S3. aws cli returned non-zero exit status.")
        if stderr:
            print(f"AWS CLI stderr: {stderr}")
        sys.exit(e.returncode if isinstance(e.returncode, int) else 1)
    except FileNotFoundError:
        print("FATAL: aws CLI not found on PATH. Ensure AWS CLI is installed in the environment running this script.")
        sys.exit(1)


if __name__ == "__main__":
    main()
