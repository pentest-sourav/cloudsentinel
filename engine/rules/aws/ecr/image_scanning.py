from dataclasses import dataclass
from fnmatch import fnmatchcase

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECRImageScanningResult:
    repository_name: str
    scan_on_push: bool | None
    registry_scan_type: str | None
    registry_scan_frequency: str | None


def _filter_matches(
    repository_name: str,
    repository_filter: str,
) -> bool:
    if not repository_filter:
        return False

    if "*" in repository_filter:
        return fnmatchcase(repository_name, repository_filter)

    return repository_filter in repository_name


def _repository_matches_rule(
    repository_name: str,
    rule: dict,
) -> bool:
    filters = rule.get("repositoryFilters") or []

    if not filters:
        return True

    return any(
        _filter_matches(
            repository_name,
            repository_filter.get("filter", ""),
        )
        for repository_filter in filters
    )


def _effective_scan_frequency(
    repository_name: str,
    registry_scan_type: str | None,
    registry_scan_rules: list[dict],
) -> str | None:
    if not registry_scan_type:
        return None

    if not registry_scan_rules:
        if registry_scan_type == "ENHANCED":
            return "CONTINUOUS_SCAN"

        return "MANUAL"

    matching_frequencies = [
        rule.get("scanFrequency")
        for rule in registry_scan_rules
        if _repository_matches_rule(repository_name, rule)
    ]

    if "CONTINUOUS_SCAN" in matching_frequencies:
        return "CONTINUOUS_SCAN"

    if "SCAN_ON_PUSH" in matching_frequencies:
        return "SCAN_ON_PUSH"

    return "MANUAL"


def check_ecr_image_scanning(
    repository_name: str,
    scan_on_push: bool | None,
    registry_scan_type: str | None,
    registry_scan_rules: list[dict] | None,
) -> ECRImageScanningResult | None:
    registry_scan_rules = registry_scan_rules or []

    effective_frequency = _effective_scan_frequency(
        repository_name=repository_name,
        registry_scan_type=registry_scan_type,
        registry_scan_rules=registry_scan_rules,
    )

    configured = (
        scan_on_push is True
        or effective_frequency in {
            "SCAN_ON_PUSH",
            "CONTINUOUS_SCAN",
        }
    )

    if configured:
        return None

    return ECRImageScanningResult(
        repository_name=repository_name,
        scan_on_push=scan_on_push,
        registry_scan_type=registry_scan_type,
        registry_scan_frequency=effective_frequency,
    )


def build_ecr_image_scanning_finding(
    result: ECRImageScanningResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ECR-001",
        title="ECR Repository Does Not Have Image Scanning Configured",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ecr_repository",
        resource_id=result.repository_name,
        description=(
            "The ECR repository does not have image scanning configured "
            "for scan-on-push or continuous scanning."
        ),
        evidence={
            "repository_name": result.repository_name,
            "scan_on_push": result.scan_on_push,
            "registry_scan_type": result.registry_scan_type,
            "registry_scan_frequency": result.registry_scan_frequency,
        },
        remediation=(
            "Configure Amazon ECR image scanning with scan-on-push or "
            "continuous scanning for this repository."
        ),
        compliance=[
            "AWS Security Hub ECR.1",
        ],
    )
