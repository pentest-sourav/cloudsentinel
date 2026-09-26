from __future__ import annotations

from typing import Any


class CloudFrontDataCollector:
    def __init__(self, service: Any) -> None:
        self.service = service
        self._distributions: list[dict[str, Any]] | None = None

    def collect_distributions(self) -> list[dict[str, Any]]:
        if self._distributions is None:
            raw_distributions = self.service.list_distributions()
            self._distributions = [
                self._normalize_distribution(distribution)
                for distribution in raw_distributions
            ]
        return self._distributions

    @staticmethod
    def _normalize_origins(
        origins: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        if not origins:
            return []

        normalized = []

        for origin in origins.get("Items", []) or []:
            s3_origin_config = origin.get("S3OriginConfig")
            custom_origin_config = origin.get("CustomOriginConfig")

            origin_access_identity = None
            if isinstance(s3_origin_config, dict):
                origin_access_identity = s3_origin_config.get(
                    "OriginAccessIdentity"
                )

            origin_protocol_policy = None
            origin_ssl_protocols: list[str] = []

            if isinstance(custom_origin_config, dict):
                origin_protocol_policy = custom_origin_config.get(
                    "OriginProtocolPolicy"
                )

                ssl_protocols = custom_origin_config.get(
                    "OriginSslProtocols"
                )
                if isinstance(ssl_protocols, dict):
                    origin_ssl_protocols = list(
                        ssl_protocols.get("Items", []) or []
                    )

            normalized.append(
                {
                    "origin_id": origin.get("Id"),
                    "domain_name": origin.get("DomainName"),
                    "is_s3_origin": isinstance(
                        s3_origin_config, dict
                    ),
                    "origin_access_control_id": origin.get(
                        "OriginAccessControlId"
                    ),
                    "origin_access_identity": origin_access_identity,
                    "origin_protocol_policy": origin_protocol_policy,
                    "origin_ssl_protocols": origin_ssl_protocols,
                }
            )

        return normalized

    @staticmethod
    def _normalize_viewer_protocol_policies(
        distribution_config: dict[str, Any],
    ) -> list[str]:
        policies = []

        default_cache_behavior = (
            distribution_config.get("DefaultCacheBehavior") or {}
        )

        default_policy = default_cache_behavior.get(
            "ViewerProtocolPolicy"
        )
        if default_policy:
            policies.append(default_policy)

        ordered_cache_behaviors = (
            distribution_config.get("CacheBehaviors") or {}
        )

        for behavior in ordered_cache_behaviors.get("Items", []) or []:
            policy = behavior.get("ViewerProtocolPolicy")
            if policy:
                policies.append(policy)

        return policies

    @classmethod
    def _normalize_distribution(
        cls,
        distribution: dict[str, Any],
    ) -> dict[str, Any]:
        distribution_config = (
            distribution.get("DistributionConfig") or {}
        )

        origins = cls._normalize_origins(
            distribution_config.get("Origins")
        )

        s3_origins = [
            origin
            for origin in origins
            if origin.get("is_s3_origin")
        ]

        logging_config = (
            distribution_config.get("Logging") or {}
        )

        waf_web_acl_id = distribution.get("WebACLId")
        if waf_web_acl_id is None:
            waf_web_acl_id = distribution_config.get("WebACLId")

        origin_groups = (
            distribution_config.get("OriginGroups") or {}
        )

        return {
            "resource_id": distribution.get("Id"),
            "resource_type": "cloudfront_distribution",
            "domain_name": distribution.get("DomainName"),
            "enabled": distribution_config.get("Enabled", False),
            "default_root_object": distribution_config.get(
                "DefaultRootObject"
            ),
            "viewer_protocol_policies": (
                cls._normalize_viewer_protocol_policies(
                    distribution_config
                )
            ),
            "logging_enabled": bool(
                logging_config.get("Enabled", False)
            ),
            "waf_web_acl_id": waf_web_acl_id,
            "waf_enabled": bool(waf_web_acl_id),
            "origins": origins,
            "s3_origins": s3_origins,
            "origin_groups_count": len(
                origin_groups.get("Items", []) or []
            ),
        }

    def collect(self) -> list[dict[str, Any]]:
        return self.collect_distributions()
