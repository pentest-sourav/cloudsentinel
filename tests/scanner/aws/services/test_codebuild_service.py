from unittest.mock import Mock

import pytest

from scanner.aws.services.codebuild import (
    CodeBuildService,
)


@pytest.fixture
def session():
    return Mock()


@pytest.fixture
def client():
    return Mock()


@pytest.fixture
def service(
    session,
    client,
    monkeypatch,
):
    def create_client(
        _session,
        service_name,
        **kwargs,
    ):
        assert service_name == "codebuild"
        return client

    monkeypatch.setattr(
        "scanner.aws.services.codebuild.create_aws_client",
        create_client,
    )

    return CodeBuildService(session)


def test_list_project_names_paginates(
    service,
    client,
):
    client.list_projects.side_effect = [
        {
            "projects": [
                "project-a",
                "project-b",
            ],
            "nextToken": "token-1",
        },
        {
            "projects": [
                "project-c",
            ],
        },
    ]

    result = service.list_project_names()

    assert result == [
        "project-a",
        "project-b",
        "project-c",
    ]

    assert client.list_projects.call_count == 2


def test_batch_get_projects_chunks_requests(
    service,
    client,
):
    client.batch_get_projects.side_effect = [
        {
            "projects": [
                {
                    "name": "project-a",
                },
            ],
        },
        {
            "projects": [
                {
                    "name": "project-b",
                },
            ],
        },
    ]

    names = [
        f"project-{index}"
        for index in range(101)
    ]

    result = service.batch_get_projects(names)

    assert result == [
        {"name": "project-a"},
        {"name": "project-b"},
    ]

    assert client.batch_get_projects.call_count == 2


def test_list_report_group_arns_paginates(
    service,
    client,
):
    client.list_report_groups.side_effect = [
        {
            "reportGroups": [
                "arn:group:a",
            ],
            "nextToken": "token-1",
        },
        {
            "reportGroups": [
                "arn:group:b",
            ],
        },
    ]

    result = service.list_report_group_arns()

    assert result == [
        "arn:group:a",
        "arn:group:b",
    ]


def test_batch_get_report_groups(
    service,
    client,
):
    client.batch_get_report_groups.return_value = {
        "reportGroups": [
            {
                "arn": "arn:group:a",
                "name": "group-a",
            },
        ],
    }

    result = service.batch_get_report_groups(
        ["arn:group:a"]
    )

    assert result == [
        {
            "arn": "arn:group:a",
            "name": "group-a",
        }
    ]

    client.batch_get_report_groups.assert_called_once_with(
        reportGroupArns=["arn:group:a"]
    )


def test_list_projects(
    service,
    client,
):
    client.list_projects.return_value = {
        "projects": ["project-a"],
    }

    client.batch_get_projects.return_value = {
        "projects": [
            {
                "name": "project-a",
            }
        ]
    }

    result = service.list_projects()

    assert result == [
        {
            "name": "project-a",
        }
    ]


def test_list_report_groups(
    service,
    client,
):
    client.list_report_groups.return_value = {
        "reportGroups": ["arn:group:a"],
    }

    client.batch_get_report_groups.return_value = {
        "reportGroups": [
            {
                "arn": "arn:group:a",
            }
        ]
    }

    result = service.list_report_groups()

    assert result == [
        {
            "arn": "arn:group:a",
        }
    ]


def test_api_error_is_wrapped(
    service,
    client,
):
    from botocore.exceptions import ClientError

    client.list_projects.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "ListProjects",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException",
    ):
        service.list_project_names()
