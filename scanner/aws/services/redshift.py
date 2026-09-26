from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class RedshiftService:
    """
    Read-only AWS Redshift discovery service.

    AWS collection is kept separate from security evaluation.
    The service only exposes normalized API responses needed by
    the Redshift collector.
    """

    def __init__(self, session):
        self.session = session
        self.redshift_client = session.client("redshift")
        self.ec2_client = session.client("ec2")

    def describe_clusters(self) -> list[dict[str, Any]]:
        """Discover all provisioned Redshift clusters in the region."""
        try:
            paginator = self.redshift_client.get_paginator(
                "describe_clusters"
            )

            clusters: list[dict[str, Any]] = []

            for page in paginator.paginate():
                clusters.extend(page.get("Clusters", []))

            return clusters

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                f"Redshift cluster discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Redshift cluster discovery: {exc}"
            ) from exc

    def describe_cluster_parameters(
        self,
        parameter_group_name: str,
    ) -> list[dict[str, Any]]:
        """
        Return all parameters from a Redshift cluster parameter group.

        Redshift uses marker-based pagination for this operation, so
        pagination is handled explicitly.
        """
        if not parameter_group_name:
            return []

        try:
            parameters: list[dict[str, Any]] = []
            marker = None

            while True:
                kwargs = {
                    "ParameterGroupName": parameter_group_name,
                    "MaxRecords": 100,
                }

                if marker:
                    kwargs["Marker"] = marker

                response = self.redshift_client.describe_cluster_parameters(
                    **kwargs
                )

                parameters.extend(response.get("Parameters", []))

                marker = response.get("Marker")
                if not marker:
                    break

            return parameters

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                "Redshift parameter discovery failed for "
                f"{parameter_group_name}: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Redshift parameter discovery "
                f"for {parameter_group_name}: {exc}"
            ) from exc

    def describe_logging_status(
        self,
        cluster_identifier: str,
    ) -> dict[str, Any]:
        """Return Redshift audit logging status for a cluster."""
        if not cluster_identifier:
            return {}

        try:
            return self.redshift_client.describe_logging_status(
                ClusterIdentifier=cluster_identifier
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                "Redshift logging status discovery failed for "
                f"{cluster_identifier}: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Redshift logging status discovery "
                f"for {cluster_identifier}: {exc}"
            ) from exc

    def describe_security_groups(
        self,
        group_ids: list[str],
    ) -> list[dict[str, Any]]:
        """
        Describe VPC security groups associated with Redshift clusters.

        EC2 limits GroupIds requests, so IDs are processed in batches.
        """
        group_ids = list(dict.fromkeys(
            group_id for group_id in group_ids if group_id
        ))

        if not group_ids:
            return []

        try:
            security_groups: list[dict[str, Any]] = []

            for start in range(0, len(group_ids), 1000):
                batch = group_ids[start:start + 1000]
                next_token = None

                while True:
                    kwargs = {
                        "GroupIds": batch,
                        "MaxResults": 1000,
                    }

                    if next_token:
                        kwargs["NextToken"] = next_token

                    response = self.ec2_client.describe_security_groups(
                        **kwargs
                    )

                    security_groups.extend(
                        response.get("SecurityGroups", [])
                    )

                    next_token = response.get("NextToken")
                    if not next_token:
                        break

            return security_groups

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                f"Redshift security-group discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Redshift security-group discovery: "
                f"{exc}"
            ) from exc
