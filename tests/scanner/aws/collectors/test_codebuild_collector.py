from unittest.mock import Mock

from scanner.aws.collectors.codebuild import (
    CodeBuildDataCollector,
)


def test_collect_source_urls_includes_primary_and_secondary():
    service = Mock()

    service.list_projects.return_value = [
        {
            "name": "project-a",
            "arn": "arn:project:a",
            "source": {
                "type": "BITBUCKET",
                "location": (
                    "https://user:password@bitbucket.org/"
                    "org/repo"
                ),
            },
            "secondarySources": [
                {
                    "type": "BITBUCKET",
                    "location": (
                        "https://token@bitbucket.org/"
                        "org/secondary"
                    ),
                },
                {
                    "type": "GITHUB",
                    "location": (
                        "https://github.com/org/repo"
                    ),
                },
            ],
        }
    ]

    collector = CodeBuildDataCollector(service)

    result = collector.collect_source_urls()

    assert len(result) == 2
    assert result[0]["source_type"] == "BITBUCKET"
    assert result[1]["source_type"] == "BITBUCKET"


def test_collect_environment_credentials_does_not_store_values():
    service = Mock()

    service.list_projects.return_value = [
        {
            "name": "project-a",
            "arn": "arn:project:a",
            "environment": {
                "environmentVariables": [
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "secret-value",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "AWS_SECRET_ACCESS_KEY",
                        "value": "secret-value",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "NORMAL_VAR",
                        "value": "safe",
                        "type": "PLAINTEXT",
                    },
                ]
            },
        }
    ]

    collector = CodeBuildDataCollector(service)

    result = collector.collect_environment_credentials()

    assert result == [
        {
            "resource_id": "arn:project:a",
            "project_name": "project-a",
            "variable_name": "AWS_ACCESS_KEY_ID",
            "variable_type": "PLAINTEXT",
        },
        {
            "resource_id": "arn:project:a",
            "project_name": "project-a",
            "variable_name": "AWS_SECRET_ACCESS_KEY",
            "variable_type": "PLAINTEXT",
        },
    ]

    assert all(
        "value" not in entry
        for entry in result
    )


def test_collect_s3_logs():
    service = Mock()

    service.list_projects.return_value = [
        {
            "name": "project-a",
            "logsConfig": {
                "s3Logs": {
                    "status": "ENABLED",
                    "location": (
                        "arn:aws:s3:::build-logs"
                    ),
                    "encryptionDisabled": True,
                }
            },
        }
    ]

    collector = CodeBuildDataCollector(service)

    result = collector.collect_s3_logs()

    assert result == [
        {
            "resource_id": "project-a",
            "project_name": "project-a",
            "status": "ENABLED",
            "location": (
                "arn:aws:s3:::build-logs"
            ),
            "encryption_disabled": True,
        }
    ]


def test_collect_logging_configuration():
    service = Mock()

    service.list_projects.return_value = [
        {
            "name": "project-a",
            "logsConfig": {
                "cloudWatchLogs": {
                    "status": "DISABLED",
                },
                "s3Logs": {
                    "status": "ENABLED",
                },
            },
        }
    ]

    collector = CodeBuildDataCollector(service)

    result = collector.collect_logging_configuration()

    assert result == [
        {
            "resource_id": "project-a",
            "project_name": "project-a",
            "cloudwatch_status": "DISABLED",
            "s3_status": "ENABLED",
        }
    ]


def test_collect_report_group_exports():
    service = Mock()

    service.list_report_groups.return_value = [
        {
            "arn": "arn:group:a",
            "name": "group-a",
            "exportConfig": {
                "exportConfigType": "S3",
                "s3Destination": {
                    "bucket": "reports",
                    "encryptionDisabled": True,
                    "encryptionKey": "alias/test",
                },
            },
        }
    ]

    collector = CodeBuildDataCollector(service)

    result = collector.collect_report_group_exports()

    assert result == [
        {
            "resource_id": "arn:group:a",
            "report_group_name": "group-a",
            "export_config_type": "S3",
            "bucket": "reports",
            "encryption_disabled": True,
            "encryption_key": "alias/test",
        }
    ]


def test_collector_caches_projects():
    service = Mock()

    service.list_projects.return_value = []

    collector = CodeBuildDataCollector(service)

    collector.collect_source_urls()
    collector.collect_environment_credentials()

    service.list_projects.assert_called_once()


def test_collector_caches_report_groups():
    service = Mock()

    service.list_report_groups.return_value = []

    collector = CodeBuildDataCollector(service)

    collector.collect_report_group_exports()
    collector.collect_report_group_exports()

    service.list_report_groups.assert_called_once()
