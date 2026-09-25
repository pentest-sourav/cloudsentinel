from typing import Any, Callable

from scanner.aws.collectors.eks import EKSDataCollector


def collect_eks_clusters(
    collector: EKSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_clusters()


def collect_eks_nodegroups(
    collector: EKSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_nodegroups()


def collect_eks_identity_provider_configs(
    collector: EKSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_identity_provider_configs()


EKS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[EKSDataCollector], Any],
] = {
    "eks_clusters": collect_eks_clusters,
    "eks_nodegroups": collect_eks_nodegroups,
    "eks_identity_provider_configs": (
        collect_eks_identity_provider_configs
    ),
}
