from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ACMService:
    """
    Read-only AWS Certificate Manager discovery service.

    This service retrieves certificate metadata and tags only.
    Certificate private keys are never requested or returned.
    """

    def __init__(self, session):
        self.session = session
        self.acm_client = create_aws_client(
            session,
            "acm",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"ACM {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during ACM "
            f"{operation}: {exc}"
        ) from exc

    def list_certificates(self) -> list[dict[str, Any]]:
        try:
            paginator = self.acm_client.get_paginator(
                "list_certificates"
            )

            certificates: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "CertificateSummaryList",
                    [],
                )

                if isinstance(entries, list):
                    certificates.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return certificates

        except Exception as exc:
            self._raise_api_error(
                "certificate discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_certificate(
        self,
        certificate_arn: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.acm_client.describe_certificate(
                    CertificateArn=certificate_arn,
                )
            )

            certificate = response.get(
                "Certificate",
                {},
            )

            if not isinstance(certificate, dict):
                return {}

            return certificate

        except Exception as exc:
            self._raise_api_error(
                "certificate description",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags(
        self,
        certificate_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.acm_client.list_tags_for_certificate(
                CertificateArn=certificate_arn,
            )

            tags = response.get("Tags", [])

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except Exception as exc:
            self._raise_api_error(
                "certificate tag discovery",
                exc,
            )
            raise AssertionError("unreachable")
