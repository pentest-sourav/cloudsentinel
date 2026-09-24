from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class DynamoDBService:
    """
    Read-only AWS DynamoDB discovery service.

    This service retrieves DynamoDB table configuration, tags,
    continuous-backup status, DAX cluster configuration, and
    AWS Backup protected-resource information.
    """

    def __init__(self, session):
        self.session = session

        self.dynamodb_client = create_aws_client(
            session,
            "dynamodb",
        )
        self.dax_client = create_aws_client(
            session,
            "dax",
        )
        self.application_autoscaling_client = create_aws_client(
            session,
            "application-autoscaling",
        )
        self.backup_client = create_aws_client(
            session,
            "backup",
        )

    @staticmethod
    def _raise_client_error(
        exc: ClientError,
        operation: str,
    ) -> RuntimeError:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get("Message", "AWS request failed")

        return RuntimeError(
            f"DynamoDB {operation} failed: {code}: {message}"
        )

    def list_tables(self) -> list[str]:
        try:
            table_names: list[str] = []
            exclusive_start_table_name: str | None = None

            while True:
                request: dict[str, Any] = {}

                if exclusive_start_table_name:
                    request["ExclusiveStartTableName"] = (
                        exclusive_start_table_name
                    )

                response = self.dynamodb_client.list_tables(
                    **request
                )

                names = response.get("TableNames", [])

                if isinstance(names, list):
                    table_names.extend(
                        name
                        for name in names
                        if isinstance(name, str) and name
                    )

                exclusive_start_table_name = response.get(
                    "LastEvaluatedTableName"
                )

                if (
                    not isinstance(
                        exclusive_start_table_name,
                        str,
                    )
                    or not exclusive_start_table_name
                ):
                    break

            return table_names

        except ClientError as exc:
            raise self._raise_client_error(
                exc,
                "table discovery",
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during DynamoDB table discovery: {exc}"
            ) from exc

    def describe_table(
        self,
        table_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.dynamodb_client.describe_table(
                TableName=table_name,
            )

            table = response.get("Table", {})

            if not isinstance(table, dict):
                return {}

            return table

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"DynamoDB table description failed for "
                f"'{table_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while describing DynamoDB table "
                f"'{table_name}': {exc}"
            ) from exc

    def describe_continuous_backups(
        self,
        table_name: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.dynamodb_client.describe_continuous_backups(
                    TableName=table_name,
                )
            )

            description = response.get(
                "ContinuousBackupsDescription",
                {},
            )

            if not isinstance(description, dict):
                return {}

            return description

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"DynamoDB continuous backup discovery failed for "
                f"'{table_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving DynamoDB "
                f"continuous backups for '{table_name}': {exc}"
            ) from exc

    def list_table_tags(
        self,
        table_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.dynamodb_client.list_tags_of_resource(
                ResourceArn=table_arn,
            )

            tags = response.get("Tags", [])

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"DynamoDB table tag discovery failed for "
                f"'{table_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving DynamoDB "
                f"table tags for '{table_arn}': {exc}"
            ) from exc

    def describe_scalable_targets(
        self,
        table_name: str,
    ) -> dict[str, list[dict[str, Any]]]:
        targets: dict[str, list[dict[str, Any]]] = {}

        for dimension in (
            "dynamodb:table:ReadCapacityUnits",
            "dynamodb:table:WriteCapacityUnits",
        ):
            try:
                response = (
                    self.application_autoscaling_client
                    .describe_scalable_targets(
                        ServiceNamespace="dynamodb",
                        ResourceIds=[
                            f"table/{table_name}",
                        ],
                        ScalableDimension=dimension,
                    )
                )

                values = response.get(
                    "ScalableTargets",
                    [],
                )

                targets[dimension] = (
                    values if isinstance(values, list) else []
                )

            except ClientError as exc:
                error = exc.response.get("Error", {})
                code = error.get("Code", "UnknownError")

                if code == "ResourceNotFoundException":
                    targets[dimension] = []
                    continue

                message = error.get(
                    "Message",
                    "AWS request failed",
                )

                raise RuntimeError(
                    f"DynamoDB auto scaling target discovery "
                    f"failed for '{table_name}' ({dimension}): "
                    f"{code}: {message}"
                ) from exc

            except BotoCoreError as exc:
                raise RuntimeError(
                    f"AWS SDK error while retrieving DynamoDB "
                    f"auto scaling targets for '{table_name}' "
                    f"({dimension}): {exc}"
                ) from exc

        return targets

    def describe_scaling_policies(
        self,
        table_name: str,
    ) -> dict[str, list[dict[str, Any]]]:
        policies: dict[str, list[dict[str, Any]]] = {}

        for dimension in (
            "dynamodb:table:ReadCapacityUnits",
            "dynamodb:table:WriteCapacityUnits",
        ):
            try:
                response = (
                    self.application_autoscaling_client
                    .describe_scaling_policies(
                        ServiceNamespace="dynamodb",
                        ResourceId=f"table/{table_name}",
                        ScalableDimension=dimension,
                        PolicyTypes=[
                            "TargetTrackingScaling",
                        ],
                    )
                )

                values = response.get(
                    "ScalingPolicies",
                    [],
                )

                policies[dimension] = (
                    values if isinstance(values, list) else []
                )

            except ClientError as exc:
                error = exc.response.get("Error", {})
                code = error.get("Code", "UnknownError")

                if code == "ResourceNotFoundException":
                    policies[dimension] = []
                    continue

                message = error.get(
                    "Message",
                    "AWS request failed",
                )

                raise RuntimeError(
                    f"DynamoDB auto scaling policy discovery "
                    f"failed for '{table_name}' ({dimension}): "
                    f"{code}: {message}"
                ) from exc

            except BotoCoreError as exc:
                raise RuntimeError(
                    f"AWS SDK error while retrieving DynamoDB "
                    f"auto scaling policies for '{table_name}' "
                    f"({dimension}): {exc}"
                ) from exc

        return policies

    def list_dax_clusters(self) -> list[dict[str, Any]]:
        try:
            clusters: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {}

                if next_token:
                    request["NextToken"] = next_token

                response = self.dax_client.describe_clusters(
                    **request
                )

                values = response.get("Clusters", [])

                if isinstance(values, list):
                    clusters.extend(
                        cluster
                        for cluster in values
                        if isinstance(cluster, dict)
                    )

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return clusters

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"DAX cluster discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during DAX cluster discovery: {exc}"
            ) from exc

    def list_backup_protected_resources(self) -> list[dict[str, Any]]:
        try:
            resources: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {}

                if next_token:
                    request["NextToken"] = next_token

                response = self.backup_client.list_protected_resources(
                    **request
                )

                values = response.get(
                    "Results",
                    [],
                )

                if isinstance(values, list):
                    resources.extend(
                        resource
                        for resource in values
                        if isinstance(resource, dict)
                    )

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return resources

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"AWS Backup protected-resource discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during AWS Backup "
                f"protected-resource discovery: {exc}"
            ) from exc
