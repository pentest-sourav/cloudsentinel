from unittest.mock import Mock

from scanner.aws.services.ecs import ECSService


def test_list_clusters_uses_ecs_client_paginator():
    client = Mock()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "clusterArns": [
                "arn:aws:ecs:ap-south-1:123456789012:cluster/a",
            ]
        },
        {
            "clusterArns": [
                "arn:aws:ecs:ap-south-1:123456789012:cluster/b",
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    service = ECSService(client)

    result = service.list_clusters()

    assert result == [
        "arn:aws:ecs:ap-south-1:123456789012:cluster/a",
        "arn:aws:ecs:ap-south-1:123456789012:cluster/b",
    ]

    client.get_paginator.assert_called_once_with(
        "list_clusters"
    )

    paginator.paginate.assert_called_once_with()


def test_list_capacity_providers_collects_explicitly_paginated_results():
    client = Mock()

    client.describe_capacity_providers.side_effect = [
        {
            "capacityProviders": [
                {"name": "FARGATE"},
            ],
            "nextToken": "token-1",
        },
        {
            "capacityProviders": [
                {"name": "FARGATE_SPOT"},
            ],
        },
    ]

    service = ECSService(client)

    assert service.list_capacity_providers() == [
        "FARGATE",
        "FARGATE_SPOT",
    ]

    assert client.describe_capacity_providers.call_args_list == [
        ((), {"maxResults": 10}),
        ((), {"maxResults": 10, "nextToken": "token-1"}),
    ]


def test_list_capacity_providers_ignores_invalid_entries():
    client = Mock()

    client.describe_capacity_providers.return_value = {
        "capacityProviders": [
            {"name": "FARGATE"},
            None,
            "invalid",
            {"name": ""},
        ],
    }

    service = ECSService(client)

    assert service.list_capacity_providers() == [
        "FARGATE",
    ]
