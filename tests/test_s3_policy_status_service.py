from botocore.exceptions import ClientError

from scanner.aws.services.s3 import S3Service


class FakeS3Client:
    def __init__(self, response=None, error_code=None):
        self.response = response
        self.error_code = error_code

    def get_bucket_policy_status(self, Bucket):
        if self.error_code:
            error_response = {
                "Error": {
                    "Code": self.error_code,
                    "Message": "Test error",
                }
            }

            raise ClientError(
                error_response,
                "GetBucketPolicyStatus",
            )

        return self.response


class FakeSession:
    def __init__(self, response=None, error_code=None):
        self.response = response
        self.error_code = error_code

    def client(self, service_name):
        assert service_name == "s3"

        return FakeS3Client(
            response=self.response,
            error_code=self.error_code,
        )


def test_bucket_policy_status_public():
    session = FakeSession(
        response={
            "PolicyStatus": {
                "IsPublic": True,
            }
        }
    )

    service = S3Service(session)

    result = service.get_bucket_policy_status(
        "public-bucket"
    )

    assert result == {
        "IsPublic": True,
    }


def test_bucket_policy_status_not_public():
    session = FakeSession(
        response={
            "PolicyStatus": {
                "IsPublic": False,
            }
        }
    )

    service = S3Service(session)

    result = service.get_bucket_policy_status(
        "secure-bucket"
    )

    assert result == {
        "IsPublic": False,
    }


def test_bucket_policy_status_without_policy():
    session = FakeSession(
        error_code="NoSuchBucketPolicy"
    )

    service = S3Service(session)

    result = service.get_bucket_policy_status(
        "bucket-without-policy"
    )

    assert result == {}


def test_bucket_policy_status_unexpected_error():
    session = FakeSession(
        error_code="AccessDenied"
    )

    service = S3Service(session)

    try:
        service.get_bucket_policy_status(
            "restricted-bucket"
        )

        assert False, "Expected RuntimeError"

    except RuntimeError as exc:
        assert "AccessDenied" in str(exc)
