from __future__ import annotations

from typing import Any


class ECSService:
    """Thin read-only wrapper around the AWS ECS client."""

    def __init__(self, client: Any):
        self.client = client

    # ------------------------------------------------------------------
    # Clusters
    # ------------------------------------------------------------------

    def list_clusters(self) -> list[str]:
        cluster_arns: list[str] = []
        paginator = self.client.get_paginator("list_clusters")

        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))

        return cluster_arns

    def describe_clusters(
        self,
        cluster_arns: list[str],
    ) -> list[dict[str, Any]]:
        if not cluster_arns:
            return []

        response = self.client.describe_clusters(
            clusters=cluster_arns,
            include=["SETTINGS", "TAGS"],
        )

        return response.get("clusters", [])

    # ------------------------------------------------------------------
    # Capacity providers
    # ------------------------------------------------------------------

    def list_capacity_providers(self) -> list[str]:
        providers: list[str] = []
        paginator = self.client.get_paginator("describe_capacity_providers")

        for page in paginator.paginate():
            for provider in page.get("capacityProviders", []):
                name = provider.get("name")
                if name:
                    providers.append(name)

        return providers

    def describe_capacity_providers(
        self,
        capacity_provider_names: list[str],
    ) -> list[dict[str, Any]]:
        if not capacity_provider_names:
            return []

        response = self.client.describe_capacity_providers(
            capacityProviders=capacity_provider_names,
            include=["TAGS"],
        )

        return response.get("capacityProviders", [])

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def list_services(self, cluster_arn: str) -> list[str]:
        service_arns: list[str] = []
        paginator = self.client.get_paginator("list_services")

        for page in paginator.paginate(cluster=cluster_arn):
            service_arns.extend(page.get("serviceArns", []))

        return service_arns

    def describe_services(
        self,
        cluster_arn: str,
        service_arns: list[str],
    ) -> list[dict[str, Any]]:
        if not service_arns:
            return []

        response = self.client.describe_services(
            cluster=cluster_arn,
            services=service_arns,
            include=["TAGS"],
        )

        return response.get("services", [])

    # ------------------------------------------------------------------
    # Task definitions
    # ------------------------------------------------------------------

    def list_task_definitions(
        self,
        status: str = "ACTIVE",
    ) -> list[str]:
        task_definition_arns: list[str] = []
        paginator = self.client.get_paginator("list_task_definitions")

        for page in paginator.paginate(status=status):
            task_definition_arns.extend(
                page.get("taskDefinitionArns", [])
            )

        return task_definition_arns

    def describe_task_definition(
        self,
        task_definition: str,
    ) -> dict[str, Any]:
        response = self.client.describe_task_definition(
            taskDefinition=task_definition,
            include=["TAGS"],
        )

        return response.get("taskDefinition", {})

    # ------------------------------------------------------------------
    # Task sets
    # ------------------------------------------------------------------

    def list_task_sets(
        self,
        cluster_arn: str,
        service_arn: str,
    ) -> list[str]:
        response = self.client.list_task_sets(
            cluster=cluster_arn,
            service=service_arn,
        )

        return response.get("taskSets", [])

    def describe_task_sets(
        self,
        cluster_arn: str,
        service_arn: str,
        task_set_arns: list[str],
    ) -> list[dict[str, Any]]:
        if not task_set_arns:
            return []

        response = self.client.describe_task_sets(
            cluster=cluster_arn,
            service=service_arn,
            taskSets=task_set_arns,
        )

        return response.get("taskSets", [])
