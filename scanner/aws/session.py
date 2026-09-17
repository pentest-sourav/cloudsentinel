import boto3


def create_aws_session(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> boto3.Session:
    """
    Create a boto3 session using the AWS credential chain.

    If profile_name is provided, that AWS CLI profile is used.
    Otherwise boto3 uses its normal credential provider chain.
    """

    return boto3.Session(
        profile_name=profile_name,
        region_name=region_name,
    )
