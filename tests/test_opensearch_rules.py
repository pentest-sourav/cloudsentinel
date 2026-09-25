from engine.findings.model import Severity

from engine.rules.aws.opensearch.audit_logging import (
    build_opensearch_audit_logging_finding,
    check_opensearch_audit_logging,
)
from engine.rules.aws.opensearch.data_nodes import (
    build_opensearch_data_nodes_finding,
    check_opensearch_data_nodes,
)
from engine.rules.aws.opensearch.dedicated_primary_nodes import (
    build_opensearch_dedicated_primary_nodes_finding,
    check_opensearch_dedicated_primary_nodes,
)
from engine.rules.aws.opensearch.encryption_at_rest import (
    build_opensearch_encryption_at_rest_finding,
    check_opensearch_encryption_at_rest,
)
from engine.rules.aws.opensearch.error_logging import (
    build_opensearch_error_logging_finding,
    check_opensearch_error_logging,
)
from engine.rules.aws.opensearch.fine_grained_access_control import (
    build_opensearch_fine_grained_access_control_finding,
    check_opensearch_fine_grained_access_control,
)
from engine.rules.aws.opensearch.node_to_node_encryption import (
    build_opensearch_node_to_node_encryption_finding,
    check_opensearch_node_to_node_encryption,
)
from engine.rules.aws.opensearch.software_update import (
    build_opensearch_software_update_finding,
    check_opensearch_software_update,
)
from engine.rules.aws.opensearch.tagging import (
    build_opensearch_tagging_finding,
    check_opensearch_tagging,
)
from engine.rules.aws.opensearch.tls import (
    build_opensearch_tls_finding,
    check_opensearch_tls,
)
from engine.rules.aws.opensearch.vpc import (
    build_opensearch_vpc_finding,
    check_opensearch_vpc,
)


DOMAIN_ARN = (
    "arn:aws:es:ap-south-1:"
    "123456789012:domain/cloudsentinel"
)


# OpenSearch.1


def test_encryption_at_rest_passes():
    result = check_opensearch_encryption_at_rest(
        DOMAIN_ARN,
        "cloudsentinel",
        {"Enabled": True},
    )

    assert result.encryption_enabled is True
    assert build_opensearch_encryption_at_rest_finding(
        result
    ) is None


def test_encryption_at_rest_fails():
    result = check_opensearch_encryption_at_rest(
        DOMAIN_ARN,
        "cloudsentinel",
        {"Enabled": False},
    )

    finding = build_opensearch_encryption_at_rest_finding(
        result
    )

    assert result.encryption_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-001"
    assert finding.severity == Severity.MEDIUM


# OpenSearch.2


def test_vpc_passes():
    result = check_opensearch_vpc(
        DOMAIN_ARN,
        "cloudsentinel",
        {"VPCId": "vpc-123"},
    )

    assert result.vpc_enabled is True
    assert build_opensearch_vpc_finding(result) is None


def test_vpc_fails():
    result = check_opensearch_vpc(
        DOMAIN_ARN,
        "cloudsentinel",
        {},
    )

    finding = build_opensearch_vpc_finding(result)

    assert result.vpc_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-002"
    assert finding.severity == Severity.CRITICAL


# OpenSearch.3


def test_node_to_node_encryption_passes():
    result = check_opensearch_node_to_node_encryption(
        DOMAIN_ARN,
        "cloudsentinel",
        {"Enabled": True},
    )

    assert result.encryption_enabled is True
    assert (
        build_opensearch_node_to_node_encryption_finding(
            result
        )
        is None
    )


def test_node_to_node_encryption_fails():
    result = check_opensearch_node_to_node_encryption(
        DOMAIN_ARN,
        "cloudsentinel",
        {"Enabled": False},
    )

    finding = (
        build_opensearch_node_to_node_encryption_finding(
            result
        )
    )

    assert result.encryption_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-003"
    assert finding.severity == Severity.MEDIUM


# OpenSearch.4


def test_error_logging_passes():
    result = check_opensearch_error_logging(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "ES_APPLICATION_LOGS": {
                "Enabled": True,
            }
        },
    )

    assert result.error_logging_enabled is True
    assert build_opensearch_error_logging_finding(
        result
    ) is None


def test_error_logging_fails():
    result = check_opensearch_error_logging(
        DOMAIN_ARN,
        "cloudsentinel",
        {},
    )

    finding = build_opensearch_error_logging_finding(
        result
    )

    assert result.error_logging_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-004"
    assert finding.severity == Severity.MEDIUM


# OpenSearch.5


def test_audit_logging_passes():
    result = check_opensearch_audit_logging(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "AUDIT_LOGS": {
                "Enabled": True,
            }
        },
    )

    assert result.audit_logging_enabled is True
    assert build_opensearch_audit_logging_finding(
        result
    ) is None


def test_audit_logging_fails():
    result = check_opensearch_audit_logging(
        DOMAIN_ARN,
        "cloudsentinel",
        {},
    )

    finding = build_opensearch_audit_logging_finding(
        result
    )

    assert result.audit_logging_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-005"
    assert finding.severity == Severity.MEDIUM


# OpenSearch.6


def test_data_nodes_passes():
    result = check_opensearch_data_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "InstanceCount": 3,
            "ZoneAwarenessEnabled": True,
        },
    )

    assert result.instance_count == 3
    assert result.zone_awareness_enabled is True
    assert build_opensearch_data_nodes_finding(
        result
    ) is None


def test_data_nodes_fails_with_too_few_nodes():
    result = check_opensearch_data_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "InstanceCount": 2,
            "ZoneAwarenessEnabled": True,
        },
    )

    finding = build_opensearch_data_nodes_finding(
        result
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-006"
    assert finding.severity == Severity.MEDIUM


def test_data_nodes_fails_without_zone_awareness():
    result = check_opensearch_data_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "InstanceCount": 3,
            "ZoneAwarenessEnabled": False,
        },
    )

    finding = build_opensearch_data_nodes_finding(
        result
    )

    assert finding is not None


# OpenSearch.7


def test_fine_grained_access_control_passes():
    result = check_opensearch_fine_grained_access_control(
        DOMAIN_ARN,
        "cloudsentinel",
        {"Enabled": True},
    )

    assert result.access_control_enabled is True
    assert (
        build_opensearch_fine_grained_access_control_finding(
            result
        )
        is None
    )


def test_fine_grained_access_control_fails():
    result = check_opensearch_fine_grained_access_control(
        DOMAIN_ARN,
        "cloudsentinel",
        {},
    )

    finding = (
        build_opensearch_fine_grained_access_control_finding(
            result
        )
    )

    assert result.access_control_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-007"
    assert finding.severity == Severity.HIGH


# OpenSearch.8


def test_tls_passes_with_latest_policy():
    result = check_opensearch_tls(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": (
                "Policy-Min-TLS-1-2-PFS-2023-10"
            ),
        },
    )

    assert result.https_enforced is True
    assert build_opensearch_tls_finding(result) is None


def test_tls_fails_without_https():
    result = check_opensearch_tls(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "EnforceHTTPS": False,
            "TLSSecurityPolicy": (
                "Policy-Min-TLS-1-2-PFS-2023-10"
            ),
        },
    )

    finding = build_opensearch_tls_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-008"


def test_tls_fails_with_old_policy():
    result = check_opensearch_tls(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": (
                "Policy-Min-TLS-1-2-2019-07"
            ),
        },
    )

    finding = build_opensearch_tls_finding(result)

    assert finding is not None
    assert finding.severity == Severity.MEDIUM


# OpenSearch.9


def test_tagging_passes_with_non_system_tag():
    result = check_opensearch_tagging(
        DOMAIN_ARN,
        [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    )

    assert result.tagged is True
    assert build_opensearch_tagging_finding(result) is None


def test_tagging_ignores_system_tags():
    result = check_opensearch_tagging(
        DOMAIN_ARN,
        [
            {
                "Key": "aws:createdBy",
                "Value": "system",
            }
        ],
    )

    finding = build_opensearch_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-009"
    assert finding.severity == Severity.LOW


def test_tagging_fails_without_tags():
    result = check_opensearch_tagging(
        DOMAIN_ARN,
        [],
    )

    finding = build_opensearch_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None


# OpenSearch.10


def test_software_update_passes_when_none_available():
    result = check_opensearch_software_update(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "UpdateAvailable": False,
        },
    )

    assert result.update_available is False
    assert build_opensearch_software_update_finding(
        result
    ) is None


def test_software_update_fails_when_available():
    result = check_opensearch_software_update(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "CurrentVersion": "old",
            "NewVersion": "new",
            "UpdateAvailable": True,
        },
    )

    finding = build_opensearch_software_update_finding(
        result
    )

    assert result.update_available is True
    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-010"
    assert finding.severity == Severity.MEDIUM


# OpenSearch.11


def test_dedicated_primary_nodes_pass():
    result = check_opensearch_dedicated_primary_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "DedicatedMasterEnabled": True,
            "DedicatedMasterCount": 3,
        },
    )

    assert result.dedicated_master_enabled is True
    assert result.dedicated_master_count == 3
    assert (
        build_opensearch_dedicated_primary_nodes_finding(
            result
        )
        is None
    )


def test_dedicated_primary_nodes_fails_when_disabled():
    result = check_opensearch_dedicated_primary_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "DedicatedMasterEnabled": False,
            "DedicatedMasterCount": 3,
        },
    )

    finding = (
        build_opensearch_dedicated_primary_nodes_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-OPENSEARCH-011"
    assert finding.severity == Severity.LOW


def test_dedicated_primary_nodes_fails_with_fewer_than_three():
    result = check_opensearch_dedicated_primary_nodes(
        DOMAIN_ARN,
        "cloudsentinel",
        {
            "DedicatedMasterEnabled": True,
            "DedicatedMasterCount": 2,
        },
    )

    finding = (
        build_opensearch_dedicated_primary_nodes_finding(
            result
        )
    )

    assert finding is not None
