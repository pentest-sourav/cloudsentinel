from unittest.mock import Mock, patch

import pytest

from scanner.aws.region_discovery import discover_aws_regions


def test_discover_aws_regions_returns_sorted_unique_regions():
    session = Mock()

    client = Mock()
    client.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "us-west-2"},
            {"RegionName": "ap-south-1"},
            {"RegionName": "us-west-2"},
            {"RegionName": "us-east-1"},
        ]
    }

    with patch(
        "scanner.aws.region_discovery.create_aws_client",
        return_value=client,
    ):
        assert discover_aws_regions(session) == [
            "ap-south-1",
            "us-east-1",
            "us-west-2",
        ]

    client.describe_regions.assert_called_once_with(
        AllRegions=False,
    )


def test_discover_aws_regions_ignores_invalid_entries():
    session = Mock()

    client = Mock()
    client.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "ap-south-1"},
            {},
            {"RegionName": ""},
            {"RegionName": None},
            "invalid",
        ]
    }

    with patch(
        "scanner.aws.region_discovery.create_aws_client",
        return_value=client,
    ):
        assert discover_aws_regions(session) == [
            "ap-south-1",
        ]

