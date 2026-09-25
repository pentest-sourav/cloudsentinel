from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class OpenSearchService:
    """
    Read-only AWS OpenSearch Service discovery.

    Retrieves OpenSearch domain names, domain configuration,
    and resource tags required by CloudSentinel security rules.
    """

    def __init__(self, session):
        self.session = session

        self.opensearch_client = create_aws_client(
            session,
            "opensearch",
        )

    @staticmethod
    def _raise_client_error(
        exc: ClientError,
        operation: str,
    ) -> RuntimeError:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get(
            "Message",
            "AWS request failed",
        )

        return RuntimeError(
            f"OpenSearch {operation} failed: "
            f"{code}: {message}"
        )

    def list_domain_names(self) -> list[str]:
        try:
            domain_names: list[str] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {}

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.opensearch_client.list_domain_names(
                        **request
                    )
                )

                values = response.get(
                    "DomainNames",
                    [],
                )

                if isinstance(values, list):
                    for item in values:
                        if not isinstance(item, dict):
                            continue

                        name = item.get("DomainName")

                        if isinstance(name, str) and name:
                            domain_names.append(name)

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return domain_names

        except ClientError as exc:
            raise self._raise_client_error(
                exc,
                "domain discovery",
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during OpenSearch "
                f"domain discovery: {exc}"
            ) from exc

    def describe_domain(
        self,
        domain_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.opensearch_client.describe_domain(
                DomainName=domain_name,
            )

            domain = response.get(
                "DomainStatus",
                {},
            )

            if not isinstance(domain, dict):
                return {}

            return domain

        except ClientError as exc:
            raise self._raise_client_error(
                exc,
                f"domain description for '{domain_name}'",
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while describing OpenSearch "
                f"domain '{domain_name}': {exc}"
            ) from exc

    def list_tags(
        self,
        domain_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.opensearch_client.list_tags(
                ARN=domain_arn,
            )

            tags = response.get(
                "TagList",
                [],
            )

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except ClientError as exc:
            raise self._raise_client_error(
                exc,
                f"tag discovery for '{domain_arn}'",
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while retrieving OpenSearch "
                f"tags for '{domain_arn}': {exc}"
            ) from exc
