from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class CloudFrontService:
    """
    Read-only Amazon CloudFront discovery service.

    Retrieves CloudFront distributions required by
    CloudSentinel security rules.
    """

    def __init__(self, session):
        self.cloudfront_client = create_aws_client(
            session,
            "cloudfront",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS CloudFront {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during CloudFront "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during CloudFront "
            f"{operation}: {exc}"
        ) from exc

    def list_distributions(self) -> list[dict[str, Any]]:
        distributions: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxItems": "100",
                }

                if marker:
                    request["Marker"] = marker

                response = (
                    self.cloudfront_client.list_distributions(
                        **request
                    )
                )

                distribution_list = response.get(
                    "DistributionList",
                    {},
                )

                if not isinstance(
                    distribution_list,
                    dict,
                ):
                    break

                items = distribution_list.get(
                    "Items",
                    [],
                )

                if isinstance(items, list):
                    distributions.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

                if not distribution_list.get(
                    "IsTruncated",
                    False,
                ):
                    break

                next_marker = distribution_list.get(
                    "NextMarker"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return distributions

        except Exception as exc:
            self._raise_api_error(
                "distribution discovery",
                exc,
            )
            raise AssertionError("unreachable")
