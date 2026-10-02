from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.waf import WAFService


def make_service():
    session = Mock()
    session.client.side_effect = [
        Mock(),
        Mock(),
    ]

    return WAFService(session)


def test_init_creates_regional_and_cloudfront_clients():
    session = Mock()
    regional_client = Mock()
    cloudfront_client = Mock()

    session.client.side_effect = [
        regional_client,
        cloudfront_client,
    ]

    service = WAFService(session)

    assert service.regional_client is regional_client
    assert service.cloudfront_client is cloudfront_client

    assert session.client.call_count == 2

    first = session.client.call_args_list[0]
    second = session.client.call_args_list[1]

    assert first.args == ("wafv2",)
    assert second.args == ("wafv2",)
    assert second.kwargs["region_name"] == "us-east-1"


def test_list_web_acls_uses_requested_scope():
    service = make_service()

    service.regional_client.list_web_acls.side_effect = [
        {
            "WebACLs": [
                {
                    "Name": "orders",
                    "Id": "acl-1",
                    "ARN": "arn:aws:wafv2:test",
                }
            ],
            "NextMarker": "token-2",
        },
        {
            "WebACLs": [
                {
                    "Name": "payments",
                    "Id": "acl-2",
                    "ARN": "arn:aws:wafv2:test-2",
                }
            ]
        },
    ]

    result = service.list_web_acls("REGIONAL")

    assert result == [
        {
            "Name": "orders",
            "Id": "acl-1",
            "ARN": "arn:aws:wafv2:test",
        },
        {
            "Name": "payments",
            "Id": "acl-2",
            "ARN": "arn:aws:wafv2:test-2",
        },
    ]

    assert service.regional_client.list_web_acls.call_args_list[0].kwargs == {
        "Scope": "REGIONAL",
        "Limit": 100,
    }

    assert service.regional_client.list_web_acls.call_args_list[1].kwargs == {
        "Scope": "REGIONAL",
        "Limit": 100,
        "NextMarker": "token-2",
    }

    service.regional_client.get_paginator.assert_not_called()


def test_get_logging_configuration_returns_empty_when_missing():
    service = make_service()

    service.regional_client.get_logging_configuration.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "WAFNonexistentItemException",
                    "Message": "Not configured",
                }
            },
            "GetLoggingConfiguration",
        )
    )

    assert (
        service.get_logging_configuration(
            "REGIONAL",
            "arn:aws:wafv2:test",
        )
        == {}
    )


def test_list_rule_groups_uses_requested_scope():
    service = make_service()

    service.cloudfront_client.list_rule_groups.side_effect = [
        {
            "RuleGroups": [
                {
                    "Name": "managed-rules",
                    "Id": "group-1",
                    "ARN": "arn:aws:wafv2:group",
                }
            ],
            "NextMarker": "token-2",
        },
        {
            "RuleGroups": [
                {
                    "Name": "custom-rules",
                    "Id": "group-2",
                    "ARN": "arn:aws:wafv2:group-2",
                }
            ]
        },
    ]

    result = service.list_rule_groups("CLOUDFRONT")

    assert result == [
        {
            "Name": "managed-rules",
            "Id": "group-1",
            "ARN": "arn:aws:wafv2:group",
        },
        {
            "Name": "custom-rules",
            "Id": "group-2",
            "ARN": "arn:aws:wafv2:group-2",
        },
    ]

    assert service.cloudfront_client.list_rule_groups.call_args_list[0].kwargs == {
        "Scope": "CLOUDFRONT",
        "Limit": 100,
    }

    assert service.cloudfront_client.list_rule_groups.call_args_list[1].kwargs == {
        "Scope": "CLOUDFRONT",
        "Limit": 100,
        "NextMarker": "token-2",
    }

    service.cloudfront_client.get_paginator.assert_not_called()


def test_get_web_acl_returns_web_acl():
    service = make_service()

    service.regional_client.get_web_acl.return_value = {
        "WebACL": {
            "Name": "orders",
            "Id": "acl-1",
            "Rules": [],
        }
    }

    result = service.get_web_acl(
        scope="REGIONAL",
        name="orders",
        web_acl_id="acl-1",
    )

    assert result["Name"] == "orders"
    assert result["Rules"] == []


def test_get_rule_group_returns_rule_group():
    service = make_service()

    service.regional_client.get_rule_group.return_value = {
        "RuleGroup": {
            "Name": "managed-rules",
            "Id": "group-1",
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": True,
            },
        }
    }

    result = service.get_rule_group(
        scope="REGIONAL",
        name="managed-rules",
        rule_group_id="group-1",
    )

    assert result["Name"] == "managed-rules"
    assert result["VisibilityConfig"][
        "CloudWatchMetricsEnabled"
    ] is True


def test_invalid_scope_is_rejected():
    service = make_service()

    with pytest.raises(
        ValueError,
        match="Unsupported WAF scope",
    ):
        service.list_web_acls("INVALID")
