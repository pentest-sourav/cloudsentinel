from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class LambdaService:
    """
    Read-only AWS Lambda discovery service.

    This service is responsible only for collecting Lambda
    configuration data from AWS. Security evaluation is
    handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.lambda_client = session.client("lambda")

    def list_functions(self) -> list[dict[str, Any]]:
        try:
            paginator = self.lambda_client.get_paginator("list_functions")

            functions = []

            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))

            return functions

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda function discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda function discovery: {exc}"
            ) from exc

    def get_function_url_config(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        try:
            response = self.lambda_client.get_function_url_config(
                FunctionName=function_name
            )

            return {
                "function_url": response.get("FunctionUrl"),
                "auth_type": response.get("AuthType"),
                "creation_time": response.get("CreationTime"),
                "last_modified_time": response.get("LastModifiedTime"),
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda function URL discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda function URL discovery: {exc}"
            ) from exc
