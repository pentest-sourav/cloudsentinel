from unittest.mock import MagicMock

from scanner.aws.scanners.redshift import RedshiftScanner


def _base_cluster(**overrides):
    cluster = {
        "ClusterIdentifier": "cloudsentinel-redshift",
        "PubliclyAccessible": False,
        "Encrypted": True,
        "AutomatedSnapshotRetentionPeriod": 7,
        "AllowVersionUpgrade": True,
        "EnhancedVpcRouting": True,
        "MasterUsername": "cloudadmin",
        "MultiAZ": True,
        "Endpoint": {"Port": 5439},
        "ClusterParameterGroups": [
            {"ParameterGroupName": "custom-redshift"},
        ],
        "VpcSecurityGroups": [
            {"VpcSecurityGroupId": "sg-redshift"},
        ],
    }
    cluster.update(overrides)
    return cluster


def _healthy_service():
    service = MagicMock()
    service.describe_clusters.return_value = [_base_cluster()]
    service.describe_cluster_parameters.return_value = [
        {
            "ParameterName": "require_ssl",
            "ParameterValue": "true",
        }
    ]
    service.describe_logging_status.return_value = {
        "LoggingEnabled": True,
    }
    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-redshift",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5439,
                    "ToPort": 5439,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]
    return service


def test_redshift_scanner_returns_no_findings_for_secure_cluster():
    scanner = RedshiftScanner(_healthy_service())

    assert scanner.scan() == []


def test_redshift_scanner_detects_public_cluster():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(PubliclyAccessible=True)
    ]

    findings = RedshiftScanner(service).scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-REDSHIFT-001"
    assert findings[0].severity.value == "critical"


def test_redshift_scanner_detects_missing_ssl_requirement():
    service = _healthy_service()
    service.describe_cluster_parameters.return_value = [
        {
            "ParameterName": "require_ssl",
            "ParameterValue": "false",
        }
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-002"
    ]


def test_redshift_scanner_detects_insufficient_snapshot_retention():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(AutomatedSnapshotRetentionPeriod=3)
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-003"
    ]


def test_redshift_scanner_detects_disabled_audit_logging():
    service = _healthy_service()
    service.describe_logging_status.return_value = {
        "LoggingEnabled": False,
    }

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-004"
    ]


def test_redshift_scanner_detects_disabled_version_upgrade():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(AllowVersionUpgrade=False)
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-005"
    ]


def test_redshift_scanner_detects_disabled_enhanced_vpc_routing():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(EnhancedVpcRouting=False)
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-006"
    ]


def test_redshift_scanner_detects_default_admin_username():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(MasterUsername="awsuser")
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-007"
    ]


def test_redshift_scanner_detects_unencrypted_cluster():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(Encrypted=False)
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-008"
    ]


def test_redshift_scanner_detects_unrestricted_cluster_port():
    service = _healthy_service()
    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-redshift",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5439,
                    "ToPort": 5439,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-009"
    ]


def test_redshift_scanner_detects_disabled_multi_az():
    service = _healthy_service()
    service.describe_clusters.return_value = [
        _base_cluster(MultiAZ=False)
    ]

    findings = RedshiftScanner(service).scan()

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-REDSHIFT-010"
    ]


def test_redshift_scanner_handles_empty_account():
    service = MagicMock()
    service.describe_clusters.return_value = []

    scanner = RedshiftScanner(service)

    assert scanner.scan() == []
