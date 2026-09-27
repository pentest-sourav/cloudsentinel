from unittest.mock import MagicMock

from scanner.aws.collectors.vpc import VPCDataCollector


def _collector():
    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"
    return service, VPCDataCollector(service)


def test_collect_client_vpn_logging_coverage():
    service, collector = _collector()

    service.describe_client_vpn_endpoints.return_value = [
        {
            "ClientVpnEndpointId": "cvpn-1",
            "VpcId": "vpc-1",
            "ConnectionLogOptions": {"Enabled": True},
        },
        {
            "ClientVpnEndpointId": "cvpn-2",
            "VpcId": "vpc-2",
            "ConnectionLogOptions": {"Enabled": False},
        },
    ]

    assert collector.collect_client_vpn_logging_coverage() == [
        {
            "endpoint_id": "cvpn-1",
            "vpc_id": "vpc-1",
            "connection_log_enabled": True,
        },
        {
            "endpoint_id": "cvpn-2",
            "vpc_id": "vpc-2",
            "connection_log_enabled": False,
        },
    ]


def test_collect_vpn_logging_coverage_requires_two_logged_tunnels():
    service, collector = _collector()

    service.describe_vpn_connections.return_value = [
        {
            "VpnConnectionId": "vpn-1",
            "Options": {
                "TunnelOptions": [
                    {
                        "LogOptions": {
                            "CloudwatchLogOptions": {
                                "LogEnabled": True
                            }
                        }
                    },
                    {
                        "LogOptions": {
                            "CloudwatchLogOptions": {
                                "LogEnabled": False
                            }
                        }
                    },
                ]
            },
        },
        {
            "VpnConnectionId": "vpn-2",
            "Options": {
                "TunnelOptions": [
                    {
                        "LogOptions": {
                            "CloudwatchLogOptions": {
                                "LogEnabled": True
                            }
                        }
                    }
                ]
            },
        },
    ]

    assert collector.collect_vpn_logging_coverage() == [
        {
            "vpn_connection_id": "vpn-1",
            "tunnel_1_logging_enabled": True,
            "tunnel_2_logging_enabled": False,
        },
        {
            "vpn_connection_id": "vpn-2",
            "tunnel_1_logging_enabled": True,
            "tunnel_2_logging_enabled": False,
        },
    ]


def test_collect_spot_fleet_ebs_encryption_coverage_counts_unencrypted_volumes():
    service, collector = _collector()

    service.describe_spot_fleet_requests.return_value = [
        {
            "SpotFleetRequestId": "sfr-1",
            "SpotFleetRequestConfig": {
                "LaunchSpecifications": [
                    {
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/sda1",
                                "Ebs": {"Encrypted": True},
                            },
                            {
                                "DeviceName": "/dev/sdb",
                                "Ebs": {"Encrypted": False},
                            },
                            {
                                "DeviceName": "/dev/sdc",
                                "Ebs": {},
                            },
                        ]
                    }
                ]
            },
        }
    ]

    assert collector.collect_spot_fleet_ebs_encryption_coverage() == [
        {
            "spot_fleet_request_id": "sfr-1",
            "launch_parameters_present": True,
            "ebs_volume_count": 2,
            "unencrypted_volume_count": 1,
        }
    ]


def test_collect_spot_fleet_ebs_encryption_coverage_does_not_evaluate_launch_templates():
    service, collector = _collector()

    service.describe_spot_fleet_requests.return_value = [
        {
            "SpotFleetRequestId": "sfr-template",
            "SpotFleetRequestConfig": {
                "LaunchTemplateConfigs": [
                    {
                        "LaunchTemplateSpecification": {
                            "LaunchTemplateId": "lt-1",
                            "Version": "1",
                        }
                    }
                ]
            },
        }
    ]

    records = collector.collect_spot_fleet_ebs_encryption_coverage()

    assert records == [
        {
            "spot_fleet_request_id": "sfr-template",
            "launch_parameters_present": True,
            "ebs_volume_count": 0,
            "unencrypted_volume_count": 0,
        }
    ]


def test_collect_eni_source_destination_check_coverage_filters_managed_types():
    service, collector = _collector()

    service.describe_network_interfaces.return_value = [
        {
            "NetworkInterfaceId": "eni-1",
            "InterfaceType": "interface",
            "SourceDestCheck": False,
            "VpcId": "vpc-1",
            "SubnetId": "subnet-1",
        },
        {
            "NetworkInterfaceId": "eni-2",
            "InterfaceType": "nat_gateway",
            "SourceDestCheck": False,
            "VpcId": "vpc-1",
            "SubnetId": "subnet-2",
        },
    ]

    assert collector.collect_eni_source_destination_check_coverage() == [
        {
            "network_interface_id": "eni-1",
            "interface_type": "interface",
            "source_dest_check": False,
            "vpc_id": "vpc-1",
            "subnet_id": "subnet-1",
        }
    ]


def test_collect_vpn_ikev2_coverage_normalizes_values_and_missing_tunnel():
    service, collector = _collector()

    service.describe_vpn_connections.return_value = [
        {
            "VpnConnectionId": "vpn-1",
            "Options": {
                "TunnelOptions": [
                    {
                        "IkeVersions": [
                            {"Value": "IKEv2"},
                            {"Value": "ikev1"},
                        ]
                    }
                ]
            },
        }
    ]

    assert collector.collect_vpn_ikev2_coverage() == [
        {
            "vpn_connection_id": "vpn-1",
            "tunnel_1_ike_versions": ["ikev2", "ikev1"],
            "tunnel_2_ike_versions": [],
        }
    ]
