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
                origin_access_identity = (
                    s3_origin_config.get(
                        "OriginAccessIdentity"
                    )
                )

            origin_protocol_policy = None
            origin_ssl_protocols: list[str] = []

            if isinstance(custom_origin_config, dict):
                origin_protocol_policy = (
                    custom_origin_config.get(
                        "OriginProtocolPolicy"
                    )
                )

                ssl_protocols = (
                    custom_origin_config.get(
                        "OriginSslProtocols"
                    )
                )

                if isinstance(ssl_protocols, dict):
                    origin_ssl_protocols = list(
                        ssl_protocols.get(
                            "Items",
                            [],
                        )
                        or []
                    )

            normalized.append(
                {
                    "origin_id": origin.get("Id"),
                    "domain_name": origin.get(
                        "DomainName"
                    ),
                    "is_s3_origin": isinstance(
                        s3_origin_config,
                        dict,
                    ),
                    "origin_access_control_id": (
                        origin.get(
                            "OriginAccessControlId"
                        )
                    ),
                    "origin_access_identity": (
                        origin_access_identity
                    ),
                    "origin_protocol_policy": (
                        origin_protocol_policy
                    ),
                    "origin_ssl_protocols": (
                        origin_ssl_protocols
                    ),
                }
            )

        return normalized

    @staticmethod
    def _normalize_viewer_protocol_policies(
        distribution_config: dict[str, Any],
    ) -> list[str]:
        policies = []

        default_cache_behavior = (
            distribution_config.get(
                "DefaultCacheBehavior"
            )
            or {}
        )

        default_policy = default_cache_behavior.get(
            "ViewerProtocolPolicy"
        )

        if default_policy:
            policies.append(default_policy)

        ordered_cache_behaviors = (
            distribution_config.get(
                "CacheBehaviors"
            )
            or {}
        )

        for behavior in (
            ordered_cache_behaviors.get(
                "Items",
                [],
            )
            or []
        ):
            policy = behavior.get(
                "ViewerProtocolPolicy"
            )

            if policy:
                policies.append(policy)

        return policies

    @staticmethod
    def _normalize_origin_groups(
        origin_groups: dict[str, Any] | None,
    ) -> dict[str, list[str]]:
        if not origin_groups:
            return {}

        normalized: dict[str, list[str]] = {}

        for group in (
            origin_groups.get(
                "Items",
                [],
            )
            or []
        ):
            group_id = group.get("Id")

            if not group_id:
                continue

            members = group.get("Members") or {}

            origin_ids = [
                member.get("OriginId")
                for member in (
                    members.get(
                        "Items",
                        [],
                    )
                    or []
                )
                if member.get("OriginId")
            ]

            normalized[group_id] = origin_ids

        return normalized

    @staticmethod
    def _normalize_trusted_access(
        behavior: dict[str, Any],
    ) -> dict[str, Any]:
        trusted_key_groups = (
            behavior.get(
                "TrustedKeyGroups"
            )
            or {}
        )

        trusted_signers = (
            behavior.get(
                "TrustedSigners"
            )
            or {}
        )

        key_group_items = (
            trusted_key_groups.get(
                "Items",
                [],
            )
            or []
        )

        signer_items = (
            trusted_signers.get(
                "Items",
                [],
            )
            or []
        )

        return {
            "trusted_key_groups_enabled": bool(
                trusted_key_groups.get(
                    "Enabled",
                    False,
                )
            ),
            "trusted_key_group_ids": list(
                key_group_items
            ),
            "trusted_signers_enabled": bool(
                trusted_signers.get(
                    "Enabled",
                    False,
                )
            ),
            "trusted_signer_ids": list(
                signer_items
            ),
        }

    @classmethod
    def _normalize_cache_behaviors(
        cls,
        distribution_config: dict[str, Any],
        origin_groups: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        behaviors: list[dict[str, Any]] = []

        default_cache_behavior = (
            distribution_config.get(
                "DefaultCacheBehavior"
            )
            or {}
        )

        default_target = default_cache_behavior.get(
            "TargetOriginId"
        )

        default_policy = default_cache_behavior.get(
            "ViewerProtocolPolicy"
        )

        if default_target and default_policy:
            target_origin_ids = origin_groups.get(
                default_target,
                [default_target],
            )

            trusted_access = (
                cls._normalize_trusted_access(
                    default_cache_behavior
                )
            )

            behaviors.append(
                {
                    "behavior_type": "default",
                    "target_origin_id": default_target,
                    "target_origin_ids": target_origin_ids,
                    "viewer_protocol_policy": (
                        default_policy
                    ),
                    **trusted_access,
                }
            )

        ordered_cache_behaviors = (
            distribution_config.get(
                "CacheBehaviors"
            )
            or {}
        )

        for behavior in (
            ordered_cache_behaviors.get(
                "Items",
                [],
            )
            or []
        ):
            target_origin_id = behavior.get(
                "TargetOriginId"
            )

            viewer_protocol_policy = behavior.get(
                "ViewerProtocolPolicy"
            )

            if (
                not target_origin_id
                or not viewer_protocol_policy
            ):
                continue

            target_origin_ids = origin_groups.get(
                target_origin_id,
                [target_origin_id],
            )

            trusted_access = (
                cls._normalize_trusted_access(
                    behavior
                )
            )

            behaviors.append(
                {
                    "behavior_type": "ordered",
                    "target_origin_id": (
                        target_origin_id
                    ),
                    "target_origin_ids": (
                        target_origin_ids
                    ),
                    "viewer_protocol_policy": (
                        viewer_protocol_policy
                    ),
                    **trusted_access,
                }
            )

        return behaviors

    @classmethod
    def _normalize_distribution(
        cls,
        distribution: dict[str, Any],
    ) -> dict[str, Any]:
        distribution_config = (
            distribution.get(
                "DistributionConfig"
            )
            or {}
        )

        origins = cls._normalize_origins(
            distribution_config.get(
                "Origins"
            )
        )

        s3_origins = [
            origin
            for origin in origins
            if origin.get(
                "is_s3_origin"
            )
        ]

        logging_config = (
            distribution_config.get(
                "Logging"
            )
            or {}
        )

        viewer_certificate = (
            distribution_config.get(
                "ViewerCertificate"
            )
            or {}
        )

        viewer_security_policy = (
            viewer_certificate.get(
                "MinimumProtocolVersion"
            )
        )

        cloudfront_default_certificate = bool(
            viewer_certificate.get(
                "CloudFrontDefaultCertificate",
                False,
            )
        )

        ssl_support_method = (
            viewer_certificate.get(
                "SSLSupportMethod"
            )
        )

        acm_certificate_arn = (
            viewer_certificate.get(
                "ACMCertificateArn"
            )
        )

        iam_certificate_id = (
            viewer_certificate.get(
                "IAMCertificateId"
            )
        )

        waf_web_acl_id = distribution.get(
            "WebACLId"
        )

        if waf_web_acl_id is None:
            waf_web_acl_id = distribution_config.get(
                "WebACLId"
            )

        origin_groups = (
            distribution_config.get(
                "OriginGroups"
            )
            or {}
        )

        normalized_origin_groups = (
            cls._normalize_origin_groups(
                origin_groups
            )
        )

        cache_behaviors = (
            cls._normalize_cache_behaviors(
                distribution_config,
                normalized_origin_groups,
            )
        )

        return {
            "resource_id": distribution.get(
                "Id"
            ),
            "resource_type": (
                "cloudfront_distribution"
            ),
            "domain_name": distribution.get(
                "DomainName"
            ),
            "enabled": distribution_config.get(
                "Enabled",
                False,
            ),
            "default_root_object": (
                distribution_config.get(
                    "DefaultRootObject"
                )
            ),
            "viewer_protocol_policies": (
                cls._normalize_viewer_protocol_policies(
                    distribution_config
                )
            ),
            "logging_enabled": bool(
                logging_config.get(
                    "Enabled",
                    False,
                )
            ),
            "viewer_security_policy": (
                viewer_security_policy
            ),
            "cloudfront_default_certificate": (
                cloudfront_default_certificate
            ),
            "ssl_support_method": (
                ssl_support_method
            ),
            "acm_certificate_arn": (
                acm_certificate_arn
            ),
            "iam_certificate_id": (
                iam_certificate_id
            ),
            "waf_web_acl_id": waf_web_acl_id,
            "waf_enabled": bool(
                waf_web_acl_id
            ),
            "origins": origins,
            "s3_origins": s3_origins,
            "cache_behaviors": cache_behaviors,
            "origin_groups": (
                normalized_origin_groups
            ),
            "origin_groups_count": len(
                normalized_origin_groups
            ),
        }

    def collect(
        self,
    ) -> list[dict[str, Any]]:
        return self.collect_distributions()

    def collect_distributions(self) -> list[dict[str, Any]]:
        if self._distributions is None:
            raw_distributions = self.service.list_distributions()

            normalized: list[dict[str, Any]] = []

            for distribution in raw_distributions:
                item = self._normalize_distribution(
                    distribution
                )

                resource_arn = distribution.get("ARN")

                tags: list[dict[str, Any]] = []

                if isinstance(resource_arn, str) and resource_arn:
                    list_tags = getattr(
                        self.service,
                        "list_tags_for_resource",
                        None,
                    )

                    if callable(list_tags):
                        raw_tags = list_tags(resource_arn)

                        if isinstance(raw_tags, list):
                            tags = [
                                tag
                                for tag in raw_tags
                                if isinstance(tag, dict)
                            ]

                item["tags"] = tags
                normalized.append(item)

            self._distributions = normalized

        return self._distributions
