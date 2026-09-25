from typing import Any

from scanner.aws.services.ecs import ECSService


class ECSDataCollector:
    """
    Normalize Amazon ECS resources for CloudSentinel rules.
    """

    def __init__(self, service: ECSService):
        self.service = service

        self._clusters: list[dict[str, Any]] | None = None
        self._services: list[dict[str, Any]] | None = None
        self._task_definitions: list[dict[str, Any]] | None = None
        self._task_sets: list[dict[str, Any]] | None = None
        self._capacity_providers: list[dict[str, Any]] | None = None

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def collect_clusters(self) -> list[dict[str, Any]]:
        if self._clusters is not None:
            return self._clusters

        cluster_arns = self.service.list_clusters()
        raw_clusters = self.service.describe_clusters(
            cluster_arns
        )

        self._clusters = []

        for cluster in raw_clusters:
            arn = cluster.get("clusterArn")

            if not isinstance(arn, str) or not arn:
                continue

            self._clusters.append(
                {
                    "resource_id": cluster.get("clusterName")
                    or cluster.get("clusterArn"),
                    "resource_arn": arn,
                    "cluster_name": cluster.get("clusterName"),
                    "status": cluster.get("status"),
                    "settings": self._list(
                        cluster.get("settings")
                    ),
                    "tags": self._list(
                        cluster.get("tags")
                    ),
                    "resource": cluster,
                }
            )

        return self._clusters

    def collect_services(self) -> list[dict[str, Any]]:
        if self._services is not None:
            return self._services

        self._services = []

        for cluster in self.collect_clusters():
            cluster_arn = cluster["resource_arn"]

            service_arns = self.service.list_services(
                cluster_arn
            )

            raw_services = self.service.describe_services(
                cluster_arn,
                service_arns,
            )

            for service in raw_services:
                arn = service.get("serviceArn")

                if not isinstance(arn, str) or not arn:
                    continue

                self._services.append(
                    {
                        "resource_id": service.get(
                            "serviceName"
                        ) or arn,
                        "resource_arn": arn,
                        "cluster_arn": service.get(
                            "clusterArn"
                        ) or cluster_arn,
                        "service_name": service.get(
                            "serviceName"
                        ),
                        "launch_type": service.get(
                            "launchType"
                        ),
                        "platform_version": service.get(
                            "platformVersion"
                        ),
                        "task_definition": service.get(
                            "taskDefinition"
                        ),
                        "network_configuration": self._dict(
                            service.get(
                                "networkConfiguration"
                            )
                        ),
                        "tags": self._list(
                            service.get("tags")
                        ),
                        "resource": service,
                    }
                )

        return self._services

    def collect_task_definitions(
        self,
    ) -> list[dict[str, Any]]:
        if self._task_definitions is not None:
            return self._task_definitions

        arns = self.service.list_task_definitions()
        raw_definitions = (
            self.service.describe_task_definitions(arns)
        )

        self._task_definitions = []

        for definition in raw_definitions:
            arn = definition.get("taskDefinitionArn")

            if not isinstance(arn, str) or not arn:
                continue

            runtime_platform = self._dict(
                definition.get("runtimePlatform")
            )

            operating_system_family = runtime_platform.get(
                "operatingSystemFamily"
            )

            self._task_definitions.append(
                {
                    "resource_id": arn.rsplit("/", 1)[-1],
                    "resource_arn": arn,
                    "family": definition.get("family"),
                    "revision": definition.get("revision"),
                    "network_mode": definition.get(
                        "networkMode"
                    ),
                    "pid_mode": definition.get("pidMode"),
                    "container_definitions": self._list(
                        definition.get(
                            "containerDefinitions"
                        )
                    ),
                    "runtime_platform": runtime_platform,
                    "operating_system_family": (
                        operating_system_family
                    ),
                    "volumes": self._list(
                        definition.get("volumes")
                    ),
                    "tags": self._list(
                        definition.get("tags")
                    ),
                    "resource": definition,
                }
            )

        return self._task_definitions

    def collect_task_sets(self) -> list[dict[str, Any]]:
        if self._task_sets is not None:
            return self._task_sets

        self._task_sets = []

        for service in self.collect_services():
            cluster_arn = service["cluster_arn"]
            service_arn = service["resource_arn"]

            raw_task_sets = self.service.list_task_sets(
                cluster_arn,
                service_arn,
            )

            for task_set in raw_task_sets:
                arn = task_set.get("taskSetArn")

                if not isinstance(arn, str) or not arn:
                    continue

                network_configuration = self._dict(
                    task_set.get("networkConfiguration")
                )

                self._task_sets.append(
                    {
                        "resource_id": arn.rsplit("/", 1)[-1],
                        "resource_arn": arn,
                        "cluster_arn": cluster_arn,
                        "service_arn": service_arn,
                        "network_configuration": (
                            network_configuration
                        ),
                        "resource": task_set,
                    }
                )

        return self._task_sets

    def collect_capacity_providers(
        self,
    ) -> list[dict[str, Any]]:
        if self._capacity_providers is not None:
            return self._capacity_providers

        names = self.service.list_capacity_providers()
        raw_providers = (
            self.service.describe_capacity_providers(names)
        )

        self._capacity_providers = []

        for provider in raw_providers:
            arn = provider.get("capacityProviderArn")

            if not isinstance(arn, str) or not arn:
                continue

            asg_provider = self._dict(
                provider.get("autoScalingGroupProvider")
            )

            managed_scaling = self._dict(
                asg_provider.get("managedScaling")
            )

            self._capacity_providers.append(
                {
                    "resource_id": provider.get(
                        "name"
                    ) or arn.rsplit("/", 1)[-1],
                    "resource_arn": arn,
                    "name": provider.get("name"),
                    "status": provider.get("status"),
                    "auto_scaling_group_provider": asg_provider,
                    "managed_scaling": managed_scaling,
                    "managed_termination_protection": (
                        asg_provider.get(
                            "managedTerminationProtection"
                        )
                    ),
                    "resource": provider,
                }
            )

        return self._capacity_providers

    def collect(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "ecs_clusters": self.collect_clusters(),
            "ecs_services": self.collect_services(),
            "ecs_task_definitions": (
                self.collect_task_definitions()
            ),
            "ecs_task_sets": self.collect_task_sets(),
            "ecs_capacity_providers": (
                self.collect_capacity_providers()
            ),
        }
