from unittest.mock import Mock

from scanner.aws.collectors.autoscaling import (
    AutoScalingDataCollector,
)


def test_collect_auto_scaling_groups_normalizes_configuration():
    service = Mock()

    service.list_auto_scaling_groups.return_value = [
        {
            "AutoScalingGroupName": "web",
            "AutoScalingGroupARN": "arn:aws:autoscaling:group/web",
            "AvailabilityZones": [
                "ap-south-1a",
                "ap-south-1b",
            ],
            "LoadBalancerNames": ["web-lb"],
            "TargetGroupARNs": [],
            "HealthCheckType": "ELB",
            "LaunchTemplate": {
                "LaunchTemplateId": "lt-123",
            },
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
                {
                    "Key": "aws:createdBy",
                    "Value": "system",
                },
            ],
        },
    ]

    collector = AutoScalingDataCollector(service)

    result = collector.collect_auto_scaling_groups()

    assert result == [
        {
            "group_name": "web",
            "group_arn": (
                "arn:aws:autoscaling:group/web"
            ),
            "has_load_balancer": True,
            "health_check_type": "ELB",
            "availability_zones": [
                "ap-south-1a",
                "ap-south-1b",
            ],
            "availability_zone_count": 2,
            "has_launch_template": True,
            "launch_configuration_name": None,
            "launch_configuration_data_available": False,
            "metadata_http_tokens": None,
            "associate_public_ip_address": None,
            "instance_types": [
                "__single_launch_template__"
            ],
            "instance_type_count": 1,
            "instance_type_data_available": True,
            "uses_attribute_based_instance_types": False,
            "tags": {
                "Environment": "prod",
            },
            "has_non_system_tags": True,
        }
    ]

    service.list_launch_configurations.assert_not_called()


def test_collect_legacy_launch_configuration_data():
    service = Mock()

    service.list_auto_scaling_groups.return_value = [
        {
            "AutoScalingGroupName": "legacy",
            "AutoScalingGroupARN": "arn:legacy",
            "AvailabilityZones": ["ap-south-1a"],
            "LaunchConfigurationName": "legacy-config",
            "Tags": [],
        }
    ]

    service.list_launch_configurations.return_value = [
        {
            "LaunchConfigurationName": "legacy-config",
            "InstanceType": "t3.medium",
            "AssociatePublicIpAddress": True,
            "MetadataOptions": {
                "HttpTokens": "optional",
            },
        }
    ]

    collector = AutoScalingDataCollector(service)

    result = collector.collect_auto_scaling_groups()

    assert result[0]["launch_configuration_name"] == (
        "legacy-config"
    )
    assert result[0]["metadata_http_tokens"] == (
        "optional"
    )
    assert result[0]["associate_public_ip_address"] is True
    assert result[0]["instance_types"] == [
        "t3.medium"
    ]

    service.list_launch_configurations.assert_called_once_with(
        ["legacy-config"]
    )


def test_collect_auto_scaling_groups_caches_api_results():
    service = Mock()

    service.list_auto_scaling_groups.return_value = [
        {
            "AutoScalingGroupName": "web",
            "AvailabilityZones": ["a", "b"],
            "LaunchConfigurationName": "legacy",
        }
    ]

    service.list_launch_configurations.return_value = [
        {
            "LaunchConfigurationName": "legacy",
            "InstanceType": "t3.medium",
        }
    ]

    collector = AutoScalingDataCollector(service)

    first = collector.collect_auto_scaling_groups()
    second = collector.collect_auto_scaling_groups()

    assert first == second
    service.list_auto_scaling_groups.assert_called_once()
    service.list_launch_configurations.assert_called_once()
