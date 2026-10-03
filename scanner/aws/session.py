import boto3

from backend.app.core.config import settings
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


AWS_RETRY_CONFIG = Config(
    retries={
        "mode": "standard",
        "max_attempts": 5,
    },
)


def create_aws_session(
    profile_name: str | None = None,
    region_name: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    role_session_name: str = "CloudSentinelScan",
    duration_seconds: int | None = None,
) -> boto3.Session:
    """
    Create an AWS boto3 session.

    Without role_arn, boto3 uses its normal credential provider chain.

    When role_arn is provided, the initial session is used to call
    STS AssumeRole and the resulting temporary credentials are used
    to create the returned boto3 session.

    AWS clients created from the returned session should use the
    centralized CloudSentinel retry policy.

    Cross-account role assumption requires a server-generated external
    ID and requests short-lived STS credentials. The duration defaults
    to 15 minutes and is bounded to the AWS-supported 15-minute to
    12-hour range.

    No long-lived AWS credentials are stored by this function.
    """

    base_session = boto3.Session(
        profile_name=profile_name,
        region_name=region_name,
    )

    if not role_arn:
        return base_session

    if not external_id:
        raise ValueError(
            "external_id is required when assuming a cross-account AWS role."
        )

    resolved_duration_seconds = (
        settings.aws_sts_session_duration_seconds
        if duration_seconds is None
        else duration_seconds
    )

    if not 900 <= resolved_duration_seconds <= 43_200:
        raise ValueError(
            "duration_seconds must be between 900 and 43200 seconds."
        )

    if not role_session_name or not role_session_name.strip():
        raise ValueError("role_session_name must not be blank.")

    normalized_session_name = role_session_name.strip()

    if len(normalized_session_name) > 64:
        raise ValueError("role_session_name must be 64 characters or fewer.")

    sts_client = base_session.client(
        "sts",
        config=AWS_RETRY_CONFIG,
    )

    assume_role_kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": normalized_session_name,
        "DurationSeconds": resolved_duration_seconds,
        "ExternalId": external_id,
    }

    try:
        response = sts_client.assume_role(**assume_role_kwargs)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get(
            "Message",
            "AWS AssumeRole request failed",
        )

        raise RuntimeError(
            f"AWS role assumption failed: {code}: {message}"
        ) from exc
    except BotoCoreError as exc:
        raise RuntimeError(
            f"AWS SDK error during role assumption: {exc}"
        ) from exc

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region_name,
    )
