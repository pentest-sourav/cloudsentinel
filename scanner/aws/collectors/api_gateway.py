from typing import Any

from scanner.aws.services.api_gateway import APIGatewayService


class APIGatewayDataCollector:
    """
    Normalize Amazon API Gateway configuration for CloudSentinel rules.
    """

    def __init__(self, service: APIGatewayService):
        self.service = service

        self._rest_stages: list[dict[str, Any]] | None = None
        self._execution_stages: list[dict[str, Any]] | None = None
        self._v2_stages: list[dict[str, Any]] | None = None
        self._v2_routes: list[dict[str, Any]] | None = None
        self._v2_integrations: list[dict[str, Any]] | None = None
        self._domains: list[dict[str, Any]] | None = None

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def collect_rest_stages(self) -> list[dict[str, Any]]:
        if self._rest_stages is not None:
            return self._rest_stages

        normalized: list[dict[str, Any]] = []

        for api in self.service.list_rest_apis():
            rest_api_id = api.get("id")

            if not isinstance(rest_api_id, str) or not rest_api_id:
                continue

            api_name = api.get("name")

            has_http_integration = (
                self.service.rest_api_has_http_integration(
                    rest_api_id
                )
            )

            for stage in self.service.list_rest_stages(
                rest_api_id
            ):
                stage_name = stage.get("stageName")

                if not isinstance(stage_name, str) or not stage_name:
                    continue

                stage_arn = (
                    f"arn:aws:apigateway:"
                    f"{self.service.session.region_name}"
                    f"::/restapis/{rest_api_id}"
                    f"/stages/{stage_name}"
                )

                method_settings = self._dict(
                    stage.get("methodSettings")
                )

                waf = self.service.get_rest_stage_waf(
                    rest_api_id=rest_api_id,
                    stage_name=stage_name,
                )

                normalized.append(
                    {
                        "resource_id": (
                            f"{rest_api_id}:{stage_name}"
                        ),
                        "resource_arn": stage_arn,
                        "rest_api_id": rest_api_id,
                        "api_name": api_name,
                        "stage_name": stage_name,
                        "method_settings": method_settings,
                        "client_certificate_id": (
                            stage.get("clientCertificateId")
                        ),
                        "tracing_enabled": (
                            stage.get("tracingEnabled")
                        ),
                        "cache_cluster_enabled": (
                            stage.get("cacheClusterEnabled")
                        ),
                        "waf_arn": waf.get("ARN"),
                        "waf_name": waf.get("Name"),
                        "has_http_integration": (
                            has_http_integration
                        ),
                        "resource": stage,
                    }
                )

        self._rest_stages = normalized
        return normalized

    def collect_execution_stages(self) -> list[dict[str, Any]]:
        if self._execution_stages is not None:
            return self._execution_stages

        execution_stages = []

        for stage in self.collect_rest_stages():
            execution_stages.append(
                {
                    **stage,
                    "api_protocol_type": "REST",
                    "logging_level": self._rest_logging_level(
                        stage["method_settings"]
                    ),
                }
            )

        for api in self.service.list_v2_apis():
            api_id = api.get("ApiId")
            protocol_type = api.get("ProtocolType")

            if protocol_type != "WEBSOCKET":
                continue

            if not isinstance(api_id, str) or not api_id:
                continue

            for stage in self.service.list_v2_stages(api_id):
                stage_name = stage.get("StageName")

                if not isinstance(stage_name, str):
                    continue

                stage_arn = (
                    f"arn:aws:apigateway:"
                    f"{self.service.session.region_name}"
                    f"::/apis/{api_id}/stages/{stage_name}"
                )

                default_settings = self._dict(
                    stage.get("DefaultRouteSettings")
                )

                route_settings = self._dict(
                    stage.get("RouteSettings")
                )

                execution_levels = []

                default_level = default_settings.get(
                    "LoggingLevel"
                )

                if default_level:
                    execution_levels.append(default_level)

                for settings in route_settings.values():
                    if not isinstance(settings, dict):
                        continue

                    level = settings.get("LoggingLevel")

                    if level:
                        execution_levels.append(level)

                logging_level = (
                    execution_levels[0]
                    if execution_levels
                    else None
                )

                if any(
                    level not in {"ERROR", "INFO"}
                    for level in execution_levels
                ):
                    logging_level = "OFF"

                execution_stages.append(
                    {
                        "resource_id": f"{api_id}:{stage_name}",
                        "resource_arn": stage_arn,
                        "api_id": api_id,
                        "api_name": api.get("Name"),
                        "stage_name": stage_name,
                        "api_protocol_type": protocol_type,
                        "logging_level": logging_level,
                        "resource": stage,
                    }
                )

        self._execution_stages = execution_stages
        return execution_stages

    @staticmethod
    def _rest_logging_level(
        method_settings: dict[str, Any],
    ) -> str | None:
        if not method_settings:
            return None

        levels = []

        for settings in method_settings.values():
            if not isinstance(settings, dict):
                return "OFF"

            level = settings.get("loggingLevel")

            if level is None:
                return "OFF"

            levels.append(level)

        if not levels:
            return None

        if any(level not in {"ERROR", "INFO"} for level in levels):
            return "OFF"

        return levels[0]

    def collect_v2_stages(self) -> list[dict[str, Any]]:
        if self._v2_stages is not None:
            return self._v2_stages

        normalized: list[dict[str, Any]] = []

        for api in self.service.list_v2_apis():
            api_id = api.get("ApiId")

            if not isinstance(api_id, str) or not api_id:
                continue

            for stage in self.service.list_v2_stages(api_id):
                stage_name = stage.get("StageName")

                if not isinstance(stage_name, str):
                    continue

                stage_arn = (
                    f"arn:aws:apigateway:"
                    f"{self.service.session.region_name}"
                    f"::/apis/{api_id}/stages/{stage_name}"
                )

                normalized.append(
                    {
                        "resource_id": f"{api_id}:{stage_name}",
                        "resource_arn": stage_arn,
                        "api_id": api_id,
                        "api_name": api.get("Name"),
                        "protocol_type": api.get(
                            "ProtocolType"
                        ),
                        "stage_name": stage_name,
                        "access_log_settings": (
                            self._dict(
                                stage.get(
                                    "AccessLogSettings"
                                )
                            )
                        ),
                        "default_route_settings": (
                            self._dict(
                                stage.get(
                                    "DefaultRouteSettings"
                                )
                            )
                        ),
                        "resource": stage,
                    }
                )

        self._v2_stages = normalized
        return normalized

    def collect_v2_routes(self) -> list[dict[str, Any]]:
        if self._v2_routes is not None:
            return self._v2_routes

        normalized: list[dict[str, Any]] = []

        for api in self.service.list_v2_apis():
            api_id = api.get("ApiId")

            if not isinstance(api_id, str) or not api_id:
                continue

            for route in self.service.list_v2_routes(api_id):
                route_id = route.get("RouteId")

                if not isinstance(route_id, str):
                    continue

                normalized.append(
                    {
                        "resource_id": f"{api_id}:{route_id}",
                        "resource_arn": (
                            f"arn:aws:apigateway:"
                            f"{self.service.session.region_name}"
                            f"::/apis/{api_id}/routes/{route_id}"
                        ),
                        "api_id": api_id,
                        "api_name": api.get("Name"),
                        "protocol_type": api.get(
                            "ProtocolType"
                        ),
                        "route_id": route_id,
                        "route_key": route.get("RouteKey"),
                        "authorization_type": route.get(
                            "AuthorizationType"
                        ),
                        "resource": route,
                    }
                )

        self._v2_routes = normalized
        return normalized

    def collect_v2_integrations(
        self,
    ) -> list[dict[str, Any]]:
        if self._v2_integrations is not None:
            return self._v2_integrations

        normalized: list[dict[str, Any]] = []

        for api in self.service.list_v2_apis():
            api_id = api.get("ApiId")

            if not isinstance(api_id, str) or not api_id:
                continue

            for integration in self.service.list_v2_integrations(
                api_id
            ):
                integration_id = integration.get(
                    "IntegrationId"
                )

                if not isinstance(integration_id, str):
                    continue

                normalized.append(
                    {
                        "resource_id": (
                            f"{api_id}:{integration_id}"
                        ),
                        "resource_arn": (
                            f"arn:aws:apigateway:"
                            f"{self.service.session.region_name}"
                            f"::/apis/{api_id}"
                            f"/integrations/{integration_id}"
                        ),
                        "api_id": api_id,
                        "api_name": api.get("Name"),
                        "protocol_type": api.get(
                            "ProtocolType"
                        ),
                        "integration_id": integration_id,
                        "integration_type": integration.get(
                            "IntegrationType"
                        ),
                        "connection_type": integration.get(
                            "ConnectionType"
                        ),
                        "tls_config": self._dict(
                            integration.get("TlsConfig")
                        ),
                        "resource": integration,
                    }
                )

        self._v2_integrations = normalized
        return normalized

    def collect_domains(self) -> list[dict[str, Any]]:
        if self._domains is not None:
            return self._domains

        normalized: list[dict[str, Any]] = []

        for domain in self.service.list_rest_domain_names():
            name = domain.get("domainName")

            if not isinstance(name, str) or not name:
                continue

            normalized.append(
                {
                    "resource_id": name,
                    "resource_arn": (
                        f"arn:aws:apigateway:"
                        f"{self.service.session.region_name}"
                        f"::/domainnames/{name}"
                    ),
                    "domain_name": name,
                    "security_policy": domain.get(
                        "securityPolicy"
                    ),
                    "endpoint_configuration": (
                        self._dict(
                            domain.get(
                                "endpointConfiguration"
                            )
                        )
                    ),
                    "resource": domain,
                }
            )

        self._domains = normalized
        return normalized
