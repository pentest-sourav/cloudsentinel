from unittest.mock import Mock

from scanner.aws.collectors.glue import GlueDataCollector


def test_collect_jobs_normalizes_tags_and_spark_fields():
    service = Mock()

    service.list_jobs.return_value = [
        {
            "Name": "etl-prod",
            "JobArn": (
                "arn:aws:glue:ap-south-1:"
                "123456789012:job/etl-prod"
            ),
            "GlueVersion": "5.0",
            "Command": {"Name": "glueetl"},
        }
    ]

    service.get_tags.return_value = {
        "Environment": "prod",
        "aws:createdBy": "system",
    }

    collector = GlueDataCollector(service)

    result = collector.collect_jobs()

    assert result == [
        {
            "job_name": "etl-prod",
            "job_arn": (
                "arn:aws:glue:ap-south-1:"
                "123456789012:job/etl-prod"
            ),
            "glue_version": "5.0",
            "command_name": "glueetl",
            "tags": {"Environment": "prod"},
            "has_non_system_tags": True,
        }
    ]

    service.get_tags.assert_called_once()


def test_collect_jobs_without_tags_is_detected():
    service = Mock()

    service.list_jobs.return_value = [
        {
            "Name": "untagged-job",
            "JobArn": "arn:aws:glue:job/untagged-job",
            "GlueVersion": "5.0",
            "Command": {"Name": "glueetl"},
        }
    ]

    service.get_tags.return_value = {}

    collector = GlueDataCollector(service)

    result = collector.collect_jobs()

    assert result[0]["has_non_system_tags"] is False
    assert result[0]["tags"] == {}


def test_collect_jobs_filters_system_tags():
    service = Mock()

    service.list_jobs.return_value = [
        {
            "Name": "system-only",
            "JobArn": "arn:aws:glue:job/system-only",
        }
    ]

    service.get_tags.return_value = {
        "aws:cloudformation:stack-id": "stack",
    }

    collector = GlueDataCollector(service)

    result = collector.collect_jobs()

    assert result[0]["has_non_system_tags"] is False
    assert result[0]["tags"] == {}


def test_collect_jobs_caches_jobs_and_tags():
    service = Mock()

    service.list_jobs.return_value = [
        {
            "Name": "job-1",
            "JobArn": "arn:aws:glue:job/job-1",
        }
    ]

    service.get_tags.return_value = {
        "Environment": "prod",
    }

    collector = GlueDataCollector(service)

    collector.collect_jobs()
    collector.collect_jobs()

    service.list_jobs.assert_called_once()
    service.get_tags.assert_called_once_with(
        "arn:aws:glue:job/job-1"
    )


def test_collect_ml_transforms_normalizes_encryption():
    service = Mock()

    service.list_ml_transforms.return_value = [
        {
            "TransformId": "transform-1",
            "Name": "customer-match",
            "GlueVersion": "5.0",
            "TransformEncryption": {
                "MlUserDataEncryption": {
                    "MlUserDataEncryptionMode": "SSEKMS",
                    "KmsKeyId": "key-123",
                },
                "TaskRunSecurityConfigurationName": (
                    "secure-config"
                ),
            },
        }
    ]

    collector = GlueDataCollector(service)

    result = collector.collect_ml_transforms()

    assert result == [
        {
            "transform_id": "transform-1",
            "transform_name": "customer-match",
            "glue_version": "5.0",
            "encryption_mode": "SSEKMS",
            "kms_key_id": "key-123",
            "task_run_security_configuration_name": (
                "secure-config"
            ),
        }
    ]


def test_collect_ml_transforms_missing_encryption_is_unknown():
    service = Mock()

    service.list_ml_transforms.return_value = [
        {"TransformId": "transform-1"}
    ]

    collector = GlueDataCollector(service)

    result = collector.collect_ml_transforms()

    assert result[0]["encryption_mode"] is None
