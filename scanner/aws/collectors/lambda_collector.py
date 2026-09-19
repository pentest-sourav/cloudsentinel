from typing import Any

from scanner.aws.services.lambda_service import LambdaService


class LambdaDataCollector:
    """
    Normalizes AWS Lambda configuration data for security rules.
    """

    def __init__(self, service: LambdaService):
        self.service = service
        self._functions_cache: list[dict[str, Any]] | None = None
        self._url_config_cache: dict[str, dict[str, Any] | None] = {}

    def _get_functions(self) -> list[dict[str, Any]]:
        if self._functions_cache is None:
            self._functions_cache = self.service.list_functions()

        return self._functions_cache

    def _get_function_url_config(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        if function_name not in self._url_config_cache:
            self._url_config_cache[function_name] = (
                self.service.get_function_url_config(function_name)
            )

        return self._url_config_cache[function_name]

    def collect_functions(self) -> list[dict[str, Any]]:
        normalized = []

        for function in self._get_functions():
            function_name = function.get("FunctionName")

            if not function_name:
                continue

            url_config = self._get_function_url_config(function_name)

            normalized.append(
                {
                    "function_name": function_name,
                    "function_arn": function.get("FunctionArn"),
                    "runtime": function.get("Runtime"),
                    "role": function.get("Role"),
                    "handler": function.get("Handler"),
                    "code_size": function.get("CodeSize"),
                    "timeout": function.get("Timeout", 0),
                    "memory_size": function.get("MemorySize", 0),
                    "environment_variables": function.get(
                        "Environment", {}
                    ).get("Variables", {}),
                    "last_modified": function.get("LastModified"),
                    "function_url": (
                        url_config.get("function_url")
                        if url_config
                        else None
                    ),
                    "url_auth_type": (
                        url_config.get("auth_type")
                        if url_config
                        else None
                    ),
                }
            )

        return normalized
