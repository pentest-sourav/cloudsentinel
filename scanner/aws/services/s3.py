from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class S3Service:
    def __init__(self, session):
        self.session = session
        self.s3_client = session.client("s3")

    def list_buckets(self) -> list[dict[str, Any]]:
        response = self.s3_client.list_buckets()

        buckets = []

        for bucket in response.get("Buckets", []):
            buckets.append(
                {
                    "name": bucket["Name"],
                    "creation_date": bucket.get("CreationDate"),
                }
            )

        return buckets

    def get_public_access_block(
        self,
        bucket_name: str,
    ) -> dict[str, bool]:
        try:
            response = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )

            return response.get(
                "PublicAccessBlockConfiguration",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            if code == "NoSuchPublicAccessBlockConfiguration":
                return {}

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 Public Access Block check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 Public Access Block: "
                f"{exc}"
            ) from exc

    def get_bucket_encryption(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )

            return response.get(
                "ServerSideEncryptionConfiguration",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            if code == "ServerSideEncryptionConfigurationNotFoundError":
                return {}

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 encryption check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 encryption: "
                f"{exc}"
            ) from exc

    def get_bucket_policy_status(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_policy_status(
                Bucket=bucket_name
            )

            return response.get(
                "PolicyStatus",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            if code == "NoSuchBucketPolicy":
                return {}

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 bucket policy status check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 bucket policy status: "
                f"{exc}"
            ) from exc

    def get_bucket_acl(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_acl(
                Bucket=bucket_name
            )

            return {
                "Owner": response.get("Owner", {}),
                "Grants": response.get("Grants", []),
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 bucket ACL check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 bucket ACL: "
                f"{exc}"
            ) from exc

    def get_bucket_versioning(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_versioning(
                Bucket=bucket_name
            )

            return {
                "Status": response.get("Status"),
                "MFADelete": response.get("MFADelete"),
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 bucket versioning check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 bucket versioning: "
                f"{exc}"
            ) from exc

    def get_bucket_logging(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_logging(
                Bucket=bucket_name
            )

            return response.get(
                "LoggingEnabled",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 bucket logging check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 bucket logging: "
                f"{exc}"
            ) from exc

    def get_object_lock_configuration(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_object_lock_configuration(
                Bucket=bucket_name
            )

            return response.get(
                "ObjectLockConfiguration",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            if code == "ObjectLockConfigurationNotFoundError":
                return {}

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 Object Lock configuration check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 Object Lock configuration: "
                f"{exc}"
            ) from exc

    def get_bucket_ownership_controls(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.s3_client.get_bucket_ownership_controls(
                Bucket=bucket_name
            )

            return response.get(
                "OwnershipControls",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")

            if code == "OwnershipControlsNotFoundError":
                return {}

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"S3 bucket ownership controls check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking S3 bucket ownership controls: "
                f"{exc}"
            ) from exc
