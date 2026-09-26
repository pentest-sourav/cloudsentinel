from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class DetectiveService:
    """Read-only Amazon Detective discovery service."""

    def __init__(self, session):
        self.session = session
        self.detective_client = create_aws_client(
            session,
            "detective",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"Detective {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Detective "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Detective "
            f"{operation}: {exc}"
        ) from exc

    def list_graphs(self) -> list[dict[str, Any]]:
        try:
            graphs: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token

                response = self.detective_client.list_graphs(
                    **kwargs
                )

                graph_list = response.get(
                    "GraphList",
                    [],
                )

                if isinstance(graph_list, list):
                    graphs.extend(
                        graph
                        for graph in graph_list
                        if isinstance(graph, dict)
                    )

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return graphs

        except Exception as exc:
            self._raise_api_error(
                "graph discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if not isinstance(resource_arn, str) or not resource_arn:
            return {}

        try:
            response = (
                self.detective_client.list_tags_for_resource(
                    ResourceArn=resource_arn,
                )
            )

            tags = response.get("Tags", {})

            if not isinstance(tags, dict):
                return {}

            return {
                key: str(value)
                for key, value in tags.items()
                if isinstance(key, str) and key
            }

        except Exception as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")
