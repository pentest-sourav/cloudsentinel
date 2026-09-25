
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SSMService:
    """
    Read-only AWS Systems Manager discovery service.

    Retrieves:
    - EC2 instances
    - Systems Manager managed-instance information
    - Patch/association compliance summaries
    - Self-owned SSM document permissions
    - SSM Automation logging settings
    - SSM document public-sharing settings

    This service never mutates AWS resources.
    """

    AUTOMATION_LOG_DESTINATION_SETTING = (
        "/ssm/automation/customer-script-log-destination"
    )

    PUBLIC_SHARING_SETTING = (
        "/ssm/documents/console/public-sharing-permission"
    )

    def __init__(self, session):
        self.ssm_client = create_aws_client(
            session,
            "ssm",
        )

        self.ec2_client = create_aws_client(
            session,
            "ec2",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SSM {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during SSM "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during SSM "
            f"{operation}: {exc}"
        ) from exc

    def describe_ec2_instances(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_instances"
            )

            instances: list[dict[str, Any]] = []

            for page in paginator.paginate():
                for reservation in page.get(
                    "Reservations",
                    [],
                ):
                    entries = reservation.get(
                        "Instances",
                        [],
                    )

                    if isinstance(entries, list):
                        instances.extend(
                            entry
                            for entry in entries
                            if isinstance(entry, dict)
                        )

            return instances

        except Exception as exc:
            self._raise_api_error(
                "EC2 instance discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_managed_instances(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ssm_client.get_paginator(
                "describe_instance_information"
            )

            managed_instances: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "InstanceInformationList",
                    [],
                )

                if isinstance(entries, list):
                    managed_instances.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return managed_instances

        except Exception as exc:
            self._raise_api_error(
                "managed-instance discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_resource_compliance_summaries(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ssm_client.get_paginator(
                "list_resource_compliance_summaries"
            )

            summaries: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "ResourceComplianceSummaryItems",
                    [],
                )

                if isinstance(entries, list):
                    summaries.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return summaries

        except Exception as exc:
            self._raise_api_error(
                "resource compliance discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_self_owned_documents(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ssm_client.get_paginator(
                "list_documents"
            )

            documents: list[dict[str, Any]] = []

            for page in paginator.paginate(
                Filters=[
                    {
                        "Key": "Owner",
                        "Values": ["Self"],
                    }
                ]
            ):
                entries = page.get(
                    "DocumentIdentifiers",
                    [],
                )

                if isinstance(entries, list):
                    documents.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return documents

        except Exception as exc:
            self._raise_api_error(
                "SSM document discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_document_permission(
        self,
        document_name: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.ssm_client
                .describe_document_permission(
                    Name=document_name,
                    PermissionType="Share",
                )
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "document permission discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_service_setting(
        self,
        setting_id: str,
    ) -> dict[str, Any]:
        try:
            response = self.ssm_client.get_service_setting(
                SettingId=setting_id,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                f"service setting discovery ({setting_id})",
                exc,
            )
            raise AssertionError("unreachable")

