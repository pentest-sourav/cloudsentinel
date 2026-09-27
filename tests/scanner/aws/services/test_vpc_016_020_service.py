from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.vpc import VPCService


METHOD_CASES = [
    (
        "describe_client_vpn_endpoints",
        "describe_client_vpn_endpoints",
        "ClientVpnEndpoints",
        "Client VPN endpoint discovery failed",
    ),
    (
        "describe_vpn_connections",
        "describe_vpn_connections",
        "VpnConnections",
        "VPN connection discovery failed",
    ),
    (
        "describe_spot_fleet_requests",
        "describe_spot_fleet_requests",
        "SpotFleetRequestConfigs",
        "Spot Fleet discovery failed",
    ),
    (
        "describe_network_interfaces",
        "describe_network_interfaces",
        "NetworkInterfaces",
        "Network interface discovery failed",
    ),
]


def _service():
    service = VPCService.__new__(VPCService)
    service.session = MagicMock()
    service.ec2_client = MagicMock()
    return service


@pytest.mark.parametrize(
    (
        "method_name",
        "api_name",
        "response_key",
        "_error_prefix",
    ),
    METHOD_CASES,
)
def test_vpc_new_service_methods_paginate(
    method_name,
    api_name,
    response_key,
    _error_prefix,
):
    service = _service()

    paginator = MagicMock()

    paginator.paginate.return_value = [
        {response_key: [{"Id": "1"}]},
        {response_key: [{"Id": "2"}]},
    ]

    service.ec2_client.get_paginator.return_value = paginator

    result = getattr(service, method_name)()

    assert result == [
        {"Id": "1"},
        {"Id": "2"},
    ]

    service.ec2_client.get_paginator.assert_called_once_with(
        api_name
    )

    paginator.paginate.assert_called_once_with()


@pytest.mark.parametrize(
    (
        "method_name",
        "_api_name",
        "_response_key",
        "error_prefix",
    ),
    METHOD_CASES,
)
def test_vpc_new_service_methods_wrap_client_errors(
    method_name,
    _api_name,
    _response_key,
    error_prefix,
):
    service = _service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "not allowed",
            }
        },
        method_name,
    )

    service.ec2_client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDenied: not allowed",
    ) as exc_info:
        getattr(service, method_name)()

    assert error_prefix in str(exc_info.value)
