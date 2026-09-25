from typing import Any

from scanner.aws.services.acm import ACMService


class ACMDataCollector:
    """
    Normalize AWS ACM certificate metadata for
    CloudSentinel security rules.

    Certificate private material is never collected.
    """

    def __init__(self, service: ACMService):
        self.service = service

        self._certificates_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._descriptions_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_certificates(
        self,
    ) -> list[dict[str, Any]]:
        if self._certificates_cache is None:
            self._certificates_cache = (
                self.service.list_certificates()
            )

        return self._certificates_cache

    def _get_description(
        self,
        certificate_arn: str,
    ) -> dict[str, Any]:
        if certificate_arn not in self._descriptions_cache:
            self._descriptions_cache[
                certificate_arn
            ] = self.service.describe_certificate(
                certificate_arn
            )

        return self._descriptions_cache[
            certificate_arn
        ]

    def _get_tags(
        self,
        certificate_arn: str,
    ) -> list[dict[str, Any]]:
        if certificate_arn not in self._tags_cache:
            self._tags_cache[
                certificate_arn
            ] = self.service.list_tags(
                certificate_arn
            )

        return self._tags_cache[
            certificate_arn
        ]

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> list[dict[str, str]]:
        if not isinstance(tags, list):
            return []

        normalized: list[dict[str, str]] = []

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")
            value = tag.get("Value", "")

            if not isinstance(key, str) or not key:
                continue

            normalized.append(
                {
                    "Key": key,
                    "Value": (
                        value
                        if isinstance(value, str)
                        else str(value)
                    ),
                }
            )

        return normalized

    def collect_certificates(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for entry in self._get_certificates():
            certificate_arn = entry.get(
                "CertificateArn"
            )

            if (
                not isinstance(
                    certificate_arn,
                    str,
                )
                or not certificate_arn
            ):
                continue

            details = self._get_description(
                certificate_arn
            )

            if not details:
                continue

            normalized.append(
                {
                    "resource_id": certificate_arn,
                    "resource_arn": certificate_arn,
                    "domain_name": details.get(
                        "DomainName"
                    )
                    or entry.get("DomainName"),
                    "status": details.get(
                        "Status"
                    )
                    or entry.get("Status"),
                    "type": details.get(
                        "Type"
                    )
                    or entry.get("Type"),
                    "key_algorithm": details.get(
                        "KeyAlgorithm"
                    )
                    or entry.get("KeyAlgorithm"),
                    "not_before": details.get(
                        "NotBefore"
                    ),
                    "not_after": details.get(
                        "NotAfter"
                    ),
                    "issued_at": details.get(
                        "IssuedAt"
                    ),
                    "imported_at": details.get(
                        "ImportedAt"
                    ),
                    "created_at": details.get(
                        "CreatedAt"
                    ),
                    "renewal_eligibility": details.get(
                        "RenewalEligibility"
                    ),
                    "renewal_summary": details.get(
                        "RenewalSummary"
                    ),
                    "tags": self._normalize_tags(
                        self._get_tags(
                            certificate_arn
                        )
                    ),
                    "resource": details,
                }
            )

        return normalized
