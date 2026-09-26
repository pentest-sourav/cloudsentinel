from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class RDSService:
    """
    Read-only AWS RDS discovery service.

    AWS API discovery is kept separate from security evaluation.
    All collection methods are paginated where AWS exposes a paginator.
    """

    def __init__(self, session):
        self.session = session
        self.rds_client = create_aws_client(session, "rds")

    @staticmethod
    def _raise_discovery_error(resource: str, exc: Exception) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                f"RDS {resource} discovery failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during RDS {resource} discovery: {exc}"
        ) from exc

    def _paginate(
        self,
        operation: str,
        result_key: str,
        resource: str,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.rds_client.get_paginator(operation)
            results: list[dict[str, Any]] = []

            for page in paginator.paginate(**kwargs):
                results.extend(page.get(result_key, []))

            return results

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(resource, exc)
            raise AssertionError("unreachable")

    def describe_db_instances(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_instances",
            "DBInstances",
            "DB instance",
        )

    def describe_db_clusters(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_clusters",
            "DBClusters",
            "DB cluster",
        )

    def describe_db_snapshots(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_snapshots",
            "DBSnapshots",
            "DB snapshot",
        )

    def describe_db_cluster_snapshots(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_cluster_snapshots",
            "DBClusterSnapshots",
            "DB cluster snapshot",
        )

    def describe_event_subscriptions(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_event_subscriptions",
            "EventSubscriptionsList",
            "event subscription",
        )

    def describe_db_proxies(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_proxies",
            "DBProxies",
            "DB proxy",
        )

    def describe_db_subnet_groups(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_subnet_groups",
            "DBSubnetGroups",
            "DB subnet group",
        )

    def describe_db_parameter_groups(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_parameter_groups",
            "DBParameterGroups",
            "DB parameter group",
        )

    def describe_db_security_groups(self) -> list[dict[str, Any]]:
        try:
            paginator = self.rds_client.get_paginator(
                "describe_db_security_groups"
            )
            results: list[dict[str, Any]] = []

            for page in paginator.paginate():
                results.extend(page.get("DBSecurityGroups", []))

            return results

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                "DB security group",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_snapshot_attributes(
        self,
        snapshot_identifier: str,
    ) -> dict[str, Any]:
        try:
            return self.rds_client.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=snapshot_identifier,
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                f"snapshot attributes ({snapshot_identifier})",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_cluster_snapshot_attributes(
        self,
        snapshot_identifier: str,
    ) -> dict[str, Any]:
        try:
            return self.rds_client.describe_db_cluster_snapshot_attributes(
                DBClusterSnapshotIdentifier=snapshot_identifier,
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                f"cluster snapshot attributes ({snapshot_identifier})",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_name: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.rds_client.list_tags_for_resource(
                ResourceName=resource_name,
            )
            return response.get("TagList", [])

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                f"tags ({resource_name})",
                exc,
            )
            raise AssertionError("unreachable")
