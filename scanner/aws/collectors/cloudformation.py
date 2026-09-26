from typing import Any

from scanner.aws.services.cloudformation import (
    CloudFormationService,
)


class CloudFormationDataCollector:
    """
    Normalize AWS CloudFormation stack data for CloudSentinel.

    The collector performs no security evaluation. It converts
    AWS responses into stable contracts consumed by rules.
    """

    def __init__(self, service: CloudFormationService):
        self.service = service
        self._stacks_cache: list[dict[str, Any]] | None = None

    def _get_stacks(self) -> list[dict[str, Any]]:
        if self._stacks_cache is None:
            self._stacks_cache = self.service.describe_stacks()

        return self._stacks_cache

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        """
        Return non-system tags and whether tag data was available.

        AWS system tags beginning with aws: are excluded because
        Security Hub's CloudFormation.2 control ignores them.
        """
        if not isinstance(tags, list):
            return {}, False

        normalized: dict[str, str] = {}

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")

            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            value = tag.get("Value", "")
            normalized[key] = str(value)

        return normalized, True

    @staticmethod
    def _is_deleted_stack(stack: dict[str, Any]) -> bool:
        status = stack.get("StackStatus")
        return status == "DELETE_COMPLETE"

    def collect_stacks(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for stack in self._get_stacks():
            if self._is_deleted_stack(stack):
                continue

            stack_id = stack.get("StackId")
            stack_name = stack.get("StackName")

            if not isinstance(stack_id, str) or not stack_id:
                continue

            if not isinstance(stack_name, str) or not stack_name:
                continue

            tags, tag_data_available = self._normalize_tags(
                stack.get("Tags")
            )

            termination_protection = stack.get(
                "EnableTerminationProtection"
            )

            if not isinstance(termination_protection, bool):
                termination_protection = None

            role_arn = stack.get("RoleARN")

            if not isinstance(role_arn, str) or not role_arn:
                role_arn = None

            stack_status = stack.get("StackStatus")

            if not isinstance(stack_status, str) or not stack_status:
                stack_status = None

            normalized.append(
                {
                    "stack_id": stack_id,
                    "stack_name": stack_name,
                    "stack_status": stack_status,
                    "role_arn": role_arn,
                    "termination_protection_enabled": (
                        termination_protection
                    ),
                    "tags": tags,
                    "tag_data_available": tag_data_available,
                    "has_non_system_tags": bool(tags),
                }
            )

        return normalized
