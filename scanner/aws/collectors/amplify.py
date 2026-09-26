from typing import Any

from scanner.aws.services.amplify import AmplifyService


class AmplifyDataCollector:
    """
    Normalize AWS Amplify apps and branches for CloudSentinel.

    The collector performs no security evaluation.
    It converts AWS responses into stable contracts consumed
    by the Amplify rules.
    """

    def __init__(self, service: AmplifyService):
        self.service = service
        self._apps_cache: list[dict[str, Any]] | None = None
        self._branches_cache: list[dict[str, Any]] | None = None

    def _get_apps(self) -> list[dict[str, Any]]:
        if self._apps_cache is None:
            self._apps_cache = self.service.list_apps()

        return self._apps_cache

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        """
        Return non-system tags and whether tag data was available.

        AWS system tags beginning with aws: are excluded because
        Security Hub Amplify tagging controls ignore them.
        """
        if not isinstance(tags, dict):
            return {}, False

        normalized: dict[str, str] = {}

        for key, value in tags.items():
            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = str(value)

        return normalized, True

    def _collect_app(
        self,
        app: dict[str, Any],
    ) -> dict[str, Any] | None:
        app_id = app.get("appId")
        app_arn = app.get("appArn")
        app_name = app.get("name")

        if (
            not isinstance(app_id, str)
            or not app_id
            or not isinstance(app_arn, str)
            or not app_arn
        ):
            return None

        if not isinstance(app_name, str) or not app_name:
            app_name = app_id

        raw_tags = self.service.list_tags_for_resource(
            app_arn
        )

        tags, tag_data_available = self._normalize_tags(
            raw_tags
        )

        return {
            "app_id": app_id,
            "app_arn": app_arn,
            "app_name": app_name,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

    def collect_apps(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for app in self._get_apps():
            if not isinstance(app, dict):
                continue

            collected = self._collect_app(app)

            if collected is not None:
                normalized.append(collected)

        return normalized

    def _get_branches(self) -> list[dict[str, Any]]:
        if self._branches_cache is None:
            branches: list[dict[str, Any]] = []

            for app in self._get_apps():
                app_id = app.get("appId")

                if (
                    not isinstance(app_id, str)
                    or not app_id
                ):
                    continue

                for branch in self.service.list_branches(
                    app_id
                ):
                    if not isinstance(branch, dict):
                        continue

                    branch_copy = dict(branch)
                    branch_copy["_app_id"] = app_id
                    branches.append(branch_copy)

            self._branches_cache = branches

        return self._branches_cache

    def _collect_branch(
        self,
        branch: dict[str, Any],
    ) -> dict[str, Any] | None:
        app_id = branch.get("_app_id")
        branch_arn = branch.get("branchArn")
        branch_name = branch.get("branchName")

        if (
            not isinstance(app_id, str)
            or not app_id
            or not isinstance(branch_arn, str)
            or not branch_arn
            or not isinstance(branch_name, str)
            or not branch_name
        ):
            return None

        raw_tags = self.service.list_tags_for_resource(
            branch_arn
        )

        tags, tag_data_available = self._normalize_tags(
            raw_tags
        )

        return {
            "app_id": app_id,
            "branch_arn": branch_arn,
            "branch_name": branch_name,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

    def collect_branches(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for branch in self._get_branches():
            collected = self._collect_branch(branch)

            if collected is not None:
                normalized.append(collected)

        return normalized
