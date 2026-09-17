from botocore.exceptions import ClientError

from scanner.aws.services.s3 import S3Service


class FakeS3Client:
    def __init__(self, response=None, error_code=None):
        self.response = response
        self.error_code = error_code

    def get_bucket_versioning(self, Bucket):
        if self.error_code:
            error_response = {
                "Error": {
                    "Code": self.error_code,
                    "Message": "Test error",
                }
            }

            raise ClientError(
                error_response,
                "GetBucketVersioning",
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


def test_bucket_versioning_enabled():
    session = FakeSession(
        response={
            "Status": "Enabled",
            "MFADelete": "Disabled",
        }
    )

    service = S3Service(session)

    result = service.get_bucket_versioning(
        "versioned-bucket"
    )

    assert result == {
        "Status": "Enabled",
        "MFADelete": "Disabled",
    }


def test_bucket_versioning_suspended():
    session = FakeSession(
        response={
            "Status": "Suspended",
            "MFADelete": "Disabled",
        }
    )

    service = S3Service(session)

    result = service.get_bucket_versioning(
        "suspended-bucket"
    )

    assert result == {
        "Status": "Suspended",
        "MFADelete": "Disabled",
    }


def test_bucket_versioning_not_configured():
    session = FakeSession(
        response={}
    )

    service = S3Service(session)

    result = service.get_bucket_versioning(
        "unversioned-bucket"
    )

    assert result == {
        "Status": None,
        "MFADelete": None,
    }


def test_bucket_versioning_access_denied():
    session = FakeSession(
        error_code="AccessDenied"
    )

    service = S3Service(session)

    try:
        service.get_bucket_versioning(
            "restricted-bucket"
        )

        assert False, "Expected RuntimeError"

    except RuntimeError as exc:
        assert "AccessDenied" in str(exc)
