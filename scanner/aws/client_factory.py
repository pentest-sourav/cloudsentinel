from typing import Any

import boto3
from botocore.client import BaseClient

from scanner.aws.session import AWS_RETRY_CONFIG


def create_aws_client(
    session: boto3.Session,
    service_name: str,
    **kwargs: Any,
) -> BaseClient:
    """
    Create an AWS service client using CloudSentinel's
    centralized retry configuration.

    Service-specific client options can be supplied through kwargs.
    """
    return session.client(
        service_name,
        config=AWS_RETRY_CONFIG,
        **kwargs,
    )
