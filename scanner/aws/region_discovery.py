from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


def discover_aws_regions(
    session: boto3.Session,
) -> list[str]:
    """
    Discover AWS regions that are enabled/available for the account.

    Uses EC2 DescribeRegions rather than a hard-coded region list.
    The caller's current session region is not required to be included
    separately because DescribeRegions returns the account-visible regions.
    """

    client = create_aws_client(session, "ec2")

    try:
        response = client.describe_regions(
            AllRegions=False,
        )
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get(
            "Message",
            "AWS region discovery failed",
        )

        raise RuntimeError(
            f"AWS region discovery failed: {code}: {message}"
        ) from exc
    except BotoCoreError as exc:
        raise RuntimeError(
            f"AWS SDK error during region discovery: {exc}"
        ) from exc

    regions: list[str] = []

    for region in response.get("Regions", []):
        if not isinstance(region, dict):
            continue

        region_name = region.get("RegionName")

        if isinstance(region_name, str) and region_name:
            regions.append(region_name)

    return sorted(set(regions))
