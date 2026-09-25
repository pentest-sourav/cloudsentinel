from engine.findings.model import Severity

from engine.rules.aws.ecs.cluster_tagging import (
    build_ecs_cluster_tagging_finding,
    check_ecs_cluster_tagging,
)
from engine.rules.aws.ecs.container_insights import (
    build_ecs_container_insights_finding,
    check_ecs_container_insights,
)
from engine.rules.aws.ecs.environment_secrets import (
    build_ecs_environment_secrets_finding,
    check_ecs_environment_secrets,
)
from engine.rules.aws.ecs.efs_tls import (
    build_ecs_efs_tls_finding,
    check_ecs_efs_tls,
)
from engine.rules.aws.ecs.fargate_platform import (
    build_ecs_fargate_platform_finding,
    check_ecs_fargate_platform,
)
from engine.rules.aws.ecs.linux_nonroot import (
    build_ecs_linux_nonroot_finding,
    check_ecs_linux_nonroot,
)
from engine.rules.aws.ecs.network_mode import (
    build_ecs_network_mode_finding,
    check_ecs_network_mode,
)
from engine.rules.aws.ecs.nonprivileged import (
    build_ecs_nonprivileged_finding,
    check_ecs_nonprivileged,
)
from engine.rules.aws.ecs.pid_namespace import (
    build_ecs_pid_namespace_finding,
    check_ecs_pid_namespace,
)
from engine.rules.aws.ecs.public_ip import (
    build_ecs_public_ip_finding,
    check_ecs_public_ip,
)
from engine.rules.aws.ecs.readonly_root import (
    build_ecs_readonly_root_finding,
    check_ecs_readonly_root,
)
from engine.rules.aws.ecs.service_tagging import (
    build_ecs_service_tagging_finding,
    check_ecs_service_tagging,
)
from engine.rules.aws.ecs.task_definition_tagging import (
    build_ecs_task_definition_tagging_finding,
    check_ecs_task_definition_tagging,
)
from engine.rules.aws.ecs.task_set_public_ip import (
    build_ecs_task_set_public_ip_finding,
    check_ecs_task_set_public_ip,
)
from engine.rules.aws.ecs.termination_protection import (
    build_ecs_termination_protection_finding,
    check_ecs_termination_protection,
)
from engine.rules.aws.ecs.windows_nonadmin import (
    build_ecs_windows_nonadmin_finding,
    check_ecs_windows_nonadmin,
)
from engine.rules.aws.ecs.logging import (
    build_ecs_logging_finding,
    check_ecs_logging,
)


def test_ecs_2_public_ip():
    result = check_ecs_public_ip(
        "arn:service:test",
        "service",
        {
            "awsvpcConfiguration": {
                "assignPublicIp": "ENABLED"
            }
        },
        {},
    )

    finding = build_ecs_public_ip_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ECS-002"
    assert finding.severity == Severity.HIGH


def test_ecs_3_host_pid_fails():
    result = check_ecs_pid_namespace(
        "arn:task:test",
        "task",
        "host",
        {},
    )

    assert build_ecs_pid_namespace_finding(result)


def test_ecs_4_privileged_fails():
    result = check_ecs_nonprivileged(
        "arn:task:test",
        "task",
        [
            {
                "name": "app",
                "privileged": True,
            }
        ],
        {},
    )

    assert build_ecs_nonprivileged_finding(result)


def test_ecs_5_missing_readonly_fails():
    result = check_ecs_readonly_root(
        "arn:task:test",
        "task",
        [{"name": "app"}],
        "LINUX",
        {},
    )

    assert build_ecs_readonly_root_finding(result)


def test_ecs_8_sensitive_environment_name_fails():
    result = check_ecs_environment_secrets(
        "arn:task:test",
        "task",
        [
            {
                "name": "app",
                "environment": [
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "x",
                    }
                ],
            }
        ],
        {},
    )

    assert build_ecs_environment_secrets_finding(result)


def test_ecs_9_missing_logging_fails():
    result = check_ecs_logging(
        "arn:task:test",
        "task",
        [{"name": "app"}],
        {},
    )

    assert build_ecs_logging_finding(result)


def test_ecs_10_old_fargate_platform_fails():
    result = check_ecs_fargate_platform(
        "arn:service:test",
        "service",
        "FARGATE",
        "1.3.0",
        {},
    )

    assert build_ecs_fargate_platform_finding(result)


def test_ecs_12_container_insights():
    result = check_ecs_container_insights(
        "arn:cluster:test",
        "cluster",
        [
            {
                "name": "containerInsights",
                "value": "disabled",
            }
        ],
        {},
    )

    assert build_ecs_container_insights_finding(result)


def test_ecs_13_empty_tags_fails():
    result = check_ecs_service_tagging(
        "arn:service:test",
        "service",
        [],
        {},
    )

    assert build_ecs_service_tagging_finding(result)


def test_ecs_14_empty_tags_fails():
    result = check_ecs_cluster_tagging(
        "arn:cluster:test",
        "cluster",
        [],
        {},
    )

    assert build_ecs_cluster_tagging_finding(result)


def test_ecs_15_empty_tags_fails():
    result = check_ecs_task_definition_tagging(
        "arn:task:test",
        "task",
        [],
        {},
    )

    assert build_ecs_task_definition_tagging_finding(result)


def test_ecs_16_public_ip_fails():
    result = check_ecs_task_set_public_ip(
        "arn:taskset:test",
        "taskset",
        {
            "awsvpcConfiguration": {
                "assignPublicIp": "ENABLED"
            }
        },
        {},
    )

    assert build_ecs_task_set_public_ip_finding(result)


def test_ecs_17_host_network_fails():
    result = check_ecs_network_mode(
        "arn:task:test",
        "task",
        "host",
        {},
    )

    assert build_ecs_network_mode_finding(result)


def test_ecs_18_efs_without_tls_fails():
    result = check_ecs_efs_tls(
        "arn:task:test",
        "task",
        [
            {
                "name": "data",
                "efsVolumeConfiguration": {
                    "fileSystemId": "fs-123"
                },
            }
        ],
        {},
    )

    assert build_ecs_efs_tls_finding(result)


def test_ecs_19_disabled_termination_protection_fails():
    result = check_ecs_termination_protection(
        "arn:capacity:test",
        "capacity",
        "DISABLED",
        {},
    )

    assert build_ecs_termination_protection_finding(result)


def test_ecs_20_missing_user_fails():
    result = check_ecs_linux_nonroot(
        "arn:task:test",
        "task",
        [{"name": "app"}],
        "LINUX",
        {},
    )

    assert build_ecs_linux_nonroot_finding(result)


def test_ecs_21_missing_windows_user_fails():
    result = check_ecs_windows_nonadmin(
        "arn:task:test",
        "task",
        [{"name": "app"}],
        "WINDOWS_SERVER_2022_FULL",
        {},
    )

    assert build_ecs_windows_nonadmin_finding(result)
