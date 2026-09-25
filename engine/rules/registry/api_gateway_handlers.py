from typing import Any, Callable

from scanner.aws.collectors.api_gateway import APIGatewayDataCollector


def collect_api_gateway_execution_stages(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_execution_stages()


def collect_api_gateway_rest_stages(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_rest_stages()


def collect_api_gateway_v2_stages(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_v2_stages()


def collect_api_gateway_v2_routes(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_v2_routes()


def collect_api_gateway_v2_integrations(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_v2_integrations()


def collect_api_gateway_domains(
    collector: APIGatewayDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_domains()


APIGATEWAY_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[APIGatewayDataCollector], Any],
] = {
    "api_gateway_execution_stages": (
        collect_api_gateway_execution_stages
    ),
    "api_gateway_rest_stages": (
        collect_api_gateway_rest_stages
    ),
    "api_gateway_v2_stages": (
        collect_api_gateway_v2_stages
    ),
    "api_gateway_v2_routes": (
        collect_api_gateway_v2_routes
    ),
    "api_gateway_v2_integrations": (
        collect_api_gateway_v2_integrations
    ),
    "api_gateway_domains": (
        collect_api_gateway_domains
    ),
}
