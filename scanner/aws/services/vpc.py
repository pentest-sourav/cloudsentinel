from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class VPCService:
    """
    Read-only AWS VPC discovery service.

    This service is responsible only for collecting VPC
    and Internet Gateway configuration data. Security
    evaluation is handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client("ec2")

    def describe_vpcs(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator("describe_vpcs")

            vpcs = []

            for page in paginator.paginate():
                vpcs.extend(page.get("Vpcs", []))

            return vpcs

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"VPC discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during VPC discovery: {exc}"
            ) from exc

    def describe_internet_gateways(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_internet_gateways"
            )

            internet_gateways = []

            for page in paginator.paginate():
                internet_gateways.extend(
                    page.get("InternetGateways", [])
                )

            return internet_gateways

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Internet Gateway discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Internet Gateway discovery: "
                f"{exc}"
            ) from exc
