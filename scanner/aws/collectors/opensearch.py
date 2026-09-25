from typing import Any

from scanner.aws.services.opensearch import OpenSearchService


class OpenSearchDataCollector:
    """
    Normalize AWS OpenSearch domain configuration for
    CloudSentinel security rules.
    """

    def __init__(self, service: OpenSearchService):
        self.service = service

        self._domains_cache: list[str] | None = None
        self._domain_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self._tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_domains(self) -> list[str]:
        if self._domains_cache is None:
            self._domains_cache = (
                self.service.list_domain_names()
            )

        return self._domains_cache

    def _get_domain_details(
        self,
        domain_name: str,
    ) -> dict[str, Any]:
        if domain_name not in self._domain_details_cache:
            self._domain_details_cache[domain_name] = (
                self.service.describe_domain(domain_name)
            )

        return self._domain_details_cache[domain_name]

    def _get_tags(
        self,
        domain_arn: str,
    ) -> list[dict[str, Any]]:
        if domain_arn not in self._tags_cache:
            self._tags_cache[domain_arn] = (
                self.service.list_tags(domain_arn)
            )

        return self._tags_cache[domain_arn]

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def collect_domains(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for domain_name in self._get_domains():
            domain = self._get_domain_details(
                domain_name
            )

            domain_arn = domain.get("ARN")

            if not isinstance(domain_arn, str) or not domain_arn:
                continue

            cluster_config = self._dict(
                domain.get("ClusterConfig")
            )
            vpc_options = self._dict(
                domain.get("VPCOptions")
            )
            encryption_at_rest = self._dict(
                domain.get("EncryptionAtRestOptions")
            )
            node_to_node = self._dict(
                domain.get("NodeToNodeEncryptionOptions")
            )
            log_publishing = self._dict(
                domain.get("LogPublishingOptions")
            )
            service_software = self._dict(
                domain.get("ServiceSoftwareOptions")
            )
            endpoint_options = self._dict(
                domain.get("DomainEndpointOptions")
            )
            advanced_security = self._dict(
                domain.get("AdvancedSecurityOptions")
            )

            normalized.append(
                {
                    "domain_name": domain_name,
                    "domain_arn": domain_arn,
                    "domain_id": domain.get("DomainId"),
                    "domain_processing_status": domain.get(
                        "DomainProcessingStatus"
                    ),
                    "encryption_at_rest_options": (
                        encryption_at_rest
                    ),
                    "node_to_node_encryption_options": (
                        node_to_node
                    ),
                    "vpc_options": vpc_options,
                    "log_publishing_options": (
                        log_publishing
                    ),
                    "service_software_options": (
                        service_software
                    ),
                    "domain_endpoint_options": (
                        endpoint_options
                    ),
                    "advanced_security_options": (
                        advanced_security
                    ),
                    "cluster_config": cluster_config,
                    "tags": self._get_tags(domain_arn),
                }
            )

        return normalized
