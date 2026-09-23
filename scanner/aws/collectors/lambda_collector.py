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
        self._policy_cache: dict[str, dict[str, Any] | None] = {}
        self._event_source_cache: dict[str, list[dict[str, Any]]] = {}
        self._subnet_az_cache: dict[str, str] = {}

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

    def _get_function_policy(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        if function_name not in self._policy_cache:
            self._policy_cache[function_name] = (
                self.service.get_function_policy(function_name)
            )

        return self._policy_cache[function_name]

    def _get_event_source_mappings(
        self,
        function_name: str,
    ) -> list[dict[str, Any]]:
        if function_name not in self._event_source_cache:
            self._event_source_cache[function_name] = (
                self.service.list_event_source_mappings(function_name)
            )

        return self._event_source_cache[function_name]

    def _get_subnet_availability_zones(
        self,
        subnet_ids: list[str],
    ) -> dict[str, str]:
        missing_subnets = [
            subnet_id
            for subnet_id in subnet_ids
            if subnet_id not in self._subnet_az_cache
        ]

        if missing_subnets:
            resolved = self.service.get_subnet_availability_zones(
                missing_subnets
            )
            self._subnet_az_cache.update(resolved)

        return {
            subnet_id: self._subnet_az_cache[subnet_id]
            for subnet_id in subnet_ids
            if subnet_id in self._subnet_az_cache
        }

    def collect_functions(self) -> list[dict[str, Any]]:
        normalized = []

        for function in self._get_functions():
            function_name = function.get("FunctionName")

            if not function_name:
                continue

            url_config = self._get_function_url_config(function_name)
            policy_config = self._get_function_policy(function_name)
            event_source_mappings = self._get_event_source_mappings(
                function_name
            )

            package_type = function.get("PackageType")

            vpc_config = function.get("VpcConfig") or {}
            vpc_id = vpc_config.get("VpcId")
            subnet_ids = vpc_config.get("SubnetIds") or []
            security_group_ids = vpc_config.get("SecurityGroupIds") or []

            subnet_availability_zones = (
                self._get_subnet_availability_zones(subnet_ids)
                if subnet_ids
                else {}
            )

            tracing_config = function.get("TracingConfig") or {}
            tracing_mode = tracing_config.get("Mode")

            normalized.append(
                {
                    "function_name": function_name,
                    "function_arn": function.get("FunctionArn"),
                    "runtime": function.get("Runtime"),
                    "package_type": package_type,
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
                    "function_policy": (
                        policy_config.get("policy")
                        if policy_config
                        else None
                    ),
                    "function_policy_revision_id": (
                        policy_config.get("revision_id")
                        if policy_config
                        else None
                    ),
                    "vpc_id": vpc_id,
                    "subnet_ids": subnet_ids,
                    "security_group_ids": security_group_ids,
                    "subnet_availability_zones": subnet_availability_zones,
                    "tracing_mode": tracing_mode,
                    "event_source_mappings": event_source_mappings,
                }
            )

        return normalized
