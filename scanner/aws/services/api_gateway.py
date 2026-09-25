from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class APIGatewayService:
    """
    Read-only discovery service for Amazon API Gateway.

    Covers:
    - API Gateway REST APIs
    - API Gateway V2 HTTP/WebSocket APIs
    - REST API stages
    - V2 stages/routes/integrations
    - REST custom domains
    - WAF associations for REST stages
    """

    def __init__(self, session):
        self.session = session
        self.apigateway_client = create_aws_client(
            session,
            "apigateway",
        )
        self.apigatewayv2_client = create_aws_client(
            session,
            "apigatewayv2",
        )
        self.wafv2_client = create_aws_client(
            session,
            "wafv2",
        )

    @staticmethod
    def _error_message(exc: Exception) -> str:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            return f"{code}: {message}"

        return str(exc)

    # ------------------------------------------------------------------
    # REST APIs
    # ------------------------------------------------------------------

    def list_rest_apis(self) -> list[dict[str, Any]]:
        try:
            paginator = self.apigateway_client.get_paginator(
                "get_rest_apis"
            )

            apis: list[dict[str, Any]] = []

            for page in paginator.paginate():
                apis.extend(page.get("items", []))

            return apis

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "API Gateway REST API discovery failed: "
                f"{self._error_message(exc)}"
            ) from exc

    def list_rest_stages(
        self,
        rest_api_id: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.apigateway_client.get_paginator(
                "get_stages"
            )

            stages: list[dict[str, Any]] = []

            for page in paginator.paginate(
                restApiId=rest_api_id,
            ):
                stages.extend(page.get("item", []))

            return stages

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"API Gateway REST stage discovery failed for "
                f"{rest_api_id}: {self._error_message(exc)}"
            ) from exc

    def list_rest_resources(
        self,
        rest_api_id: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.apigateway_client.get_paginator(
                "get_resources"
            )

            resources: list[dict[str, Any]] = []

            for page in paginator.paginate(
                restApiId=rest_api_id,
            ):
                resources.extend(page.get("items", []))

            return resources

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"API Gateway REST resource discovery failed for "
                f"{rest_api_id}: {self._error_message(exc)}"
            ) from exc

    def get_rest_integration(
        self,
        rest_api_id: str,
        resource_id: str,
        http_method: str,
    ) -> dict[str, Any]:
        try:
            return self.apigateway_client.get_integration(
                restApiId=rest_api_id,
                resourceId=resource_id,
                httpMethod=http_method,
            )

        except self.apigateway_client.exceptions.NotFoundException:
            return {}

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "API Gateway REST integration discovery failed: "
                f"{self._error_message(exc)}"
            ) from exc

    def rest_api_has_http_integration(
        self,
        rest_api_id: str,
    ) -> bool:
        for resource in self.list_rest_resources(rest_api_id):
            resource_id = resource.get("id")
            methods = resource.get("resourceMethods") or {}

            if not resource_id or not isinstance(methods, dict):
                continue

            for http_method in methods:
                integration = self.get_rest_integration(
                    rest_api_id=rest_api_id,
                    resource_id=resource_id,
                    http_method=http_method,
                )

                if integration.get("type") == "HTTP":
                    return True

        return False

    def get_rest_stage_waf(
        self,
        rest_api_id: str,
        stage_name: str,
    ) -> dict[str, Any]:
        stage_arn = (
            f"arn:aws:apigateway:{self.session.region_name}"
            f"::/restapis/{rest_api_id}/stages/{stage_name}"
        )

        try:
            response = self.wafv2_client.get_web_acl_for_resource(
                ResourceArn=stage_arn,
            )

            return response.get("WebACL") or {}

        except ClientError as exc:
            error = exc.response.get("Error", {})
            error_code = error.get("Code")

            if error_code in {
                "WAFNonexistentItemException",
                "WAFUnavailableEntityException",
            }:
                return {}

            raise RuntimeError(
                f"WAF association discovery failed for "
                f"{rest_api_id}/{stage_name}: "
                f"{self._error_message(exc)}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"WAF association discovery failed for "
                f"{rest_api_id}/{stage_name}: "
                f"{self._error_message(exc)}"
            ) from exc

    # ------------------------------------------------------------------
    # API Gateway V2
    # ------------------------------------------------------------------

    def list_v2_apis(self) -> list[dict[str, Any]]:
        try:
            paginator = self.apigatewayv2_client.get_paginator(
                "get_apis"
            )

            apis: list[dict[str, Any]] = []

            for page in paginator.paginate():
                apis.extend(page.get("Items", []))

            return apis

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "API Gateway V2 API discovery failed: "
                f"{self._error_message(exc)}"
            ) from exc

    def list_v2_stages(
        self,
        api_id: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.apigatewayv2_client.get_paginator(
                "get_stages"
            )

            stages: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ApiId=api_id,
            ):
                stages.extend(page.get("Items", []))

            return stages

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"API Gateway V2 stage discovery failed for "
                f"{api_id}: {self._error_message(exc)}"
            ) from exc

    def list_v2_routes(
        self,
        api_id: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.apigatewayv2_client.get_paginator(
                "get_routes"
            )

            routes: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ApiId=api_id,
            ):
                routes.extend(page.get("Items", []))

            return routes

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"API Gateway V2 route discovery failed for "
                f"{api_id}: {self._error_message(exc)}"
            ) from exc

    def list_v2_integrations(
        self,
        api_id: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.apigatewayv2_client.get_paginator(
                "get_integrations"
            )

            integrations: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ApiId=api_id,
            ):
                integrations.extend(page.get("Items", []))

            return integrations

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"API Gateway V2 integration discovery failed for "
                f"{api_id}: {self._error_message(exc)}"
            ) from exc

    def list_v2_domain_names(self) -> list[dict[str, Any]]:
        try:
            paginator = self.apigatewayv2_client.get_paginator(
                "get_domain_names"
            )

            domains: list[dict[str, Any]] = []

            for page in paginator.paginate():
                domains.extend(page.get("Items", []))

            return domains

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "API Gateway V2 domain discovery failed: "
                f"{self._error_message(exc)}"
            ) from exc

    def list_rest_domain_names(self) -> list[dict[str, Any]]:
        try:
            paginator = self.apigateway_client.get_paginator(
                "get_domain_names"
            )

            domains: list[dict[str, Any]] = []

            for page in paginator.paginate():
                domains.extend(page.get("items", []))

            return domains

        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "API Gateway REST domain discovery failed: "
                f"{self._error_message(exc)}"
            ) from exc
