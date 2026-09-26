from unittest.mock import Mock

from scanner.aws.collectors.elasticbeanstalk import (
    ElasticBeanstalkDataCollector,
)


def test_collect_environments_normalizes_security_options():
    service = Mock()

    service.list_environments.return_value = [
        {
            "EnvironmentId": "e-1",
            "EnvironmentName": "production",
            "EnvironmentArn": (
                "arn:aws:elasticbeanstalk:ap-south-1:"
                "123456789012:environment/app/production"
            ),
            "ApplicationName": "app",
            "Status": "Ready",
            "Health": "Green",
            "HealthStatus": "Ok",
        }
    ]

    service.get_configuration_settings.return_value = [
        {
            "OptionSettings": [
                {
                    "Namespace": (
                        "aws:elasticbeanstalk:"
                        "healthreporting:system"
                    ),
                    "OptionName": "SystemType",
                    "Value": "enhanced",
                },
                {
                    "Namespace": (
                        "aws:elasticbeanstalk:"
                        "managedactions"
                    ),
                    "OptionName": "ManagedActionsEnabled",
                    "Value": "true",
                },
                {
                    "Namespace": (
                        "aws:elasticbeanstalk:"
                        "managedactions"
                    ),
                    "OptionName": "UpdateLevel",
                    "Value": "minor",
                },
                {
                    "Namespace": (
                        "aws:elasticbeanstalk:"
                        "cloudwatch:logs"
                    ),
                    "OptionName": "StreamLogs",
                    "Value": "true",
                },
            ]
        }
    ]

    collector = ElasticBeanstalkDataCollector(service)

    result = collector.collect_environments()

    assert result == [
        {
            "resource_id": "e-1",
            "resource_type": (
                "elasticbeanstalk_environment"
            ),
            "resource_arn": (
                "arn:aws:elasticbeanstalk:ap-south-1:"
                "123456789012:environment/app/production"
            ),
            "environment_name": "production",
            "application_name": "app",
            "status": "Ready",
            "health": "Green",
            "health_status": "Ok",
            "enhanced_health_reporting": True,
            "managed_actions_enabled": True,
            "managed_update_level": "minor",
            "stream_logs": True,
        }
    ]


def test_collect_environments_defaults_missing_options_to_disabled():
    service = Mock()

    service.list_environments.return_value = [
        {
            "EnvironmentId": "e-2",
            "EnvironmentName": "legacy",
        }
    ]

    service.get_configuration_settings.return_value = [
        {
            "OptionSettings": []
        }
    ]

    collector = ElasticBeanstalkDataCollector(service)

    result = collector.collect_environments()

    assert result[0]["enhanced_health_reporting"] is False
    assert result[0]["managed_actions_enabled"] is False
    assert result[0]["managed_update_level"] is None
    assert result[0]["stream_logs"] is False


def test_collect_environments_caches_configuration_settings():
    service = Mock()

    service.list_environments.return_value = [
        {
            "EnvironmentId": "e-1",
            "EnvironmentName": "production",
        },
        {
            "EnvironmentId": "e-1",
            "EnvironmentName": "production",
        },
    ]

    service.get_configuration_settings.return_value = [
        {
            "OptionSettings": []
        }
    ]

    collector = ElasticBeanstalkDataCollector(service)

    collector.collect_environments()

    service.list_environments.assert_called_once()
    service.get_configuration_settings.assert_called_once_with(
        "production",
    )
