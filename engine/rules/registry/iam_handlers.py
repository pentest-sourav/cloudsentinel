from typing import Any, Callable

from scanner.aws.collectors.iam import IAMDataCollector


def collect_multiple_active_access_keys(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Aggregate existing IAM access-key collection data by user.

    The collector already caches all IAM access keys for the scan,
    so this handler reuses that data instead of introducing another
    AWS API call.
    """
    access_keys = collector.collect_iam_access_keys()

    aggregated: dict[str, dict[str, Any]] = {}

    for access_key in access_keys:
        username = access_key["username"]

        if username not in aggregated:
            aggregated[username] = {
                "username": username,
                "active_access_key_count": 0,
                "active_access_key_ids": [],
            }

        if access_key["status"] == "Active":
            aggregated[username][
                "active_access_key_count"
            ] += 1

            aggregated[username][
                "active_access_key_ids"
            ].append(
                access_key["access_key_id"]
            )

    return list(aggregated.values())


def collect_multiple_authentication_methods(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Combine IAM credential-report data with existing access-key data.

    Both data sources are already cached by IAMDataCollector, so
    IAM-018 does not introduce additional AWS API calls.
    """
    credential_report = collector.collect_credential_report()
    access_keys = collector.collect_iam_access_keys()

    active_keys_by_user: dict[str, list[str]] = {}

    for access_key in access_keys:
        if access_key["status"] != "Active":
            continue

        username = access_key["username"]

        active_keys_by_user.setdefault(
            username,
            [],
        ).append(
            access_key["access_key_id"]
        )

    results: list[dict[str, Any]] = []

    for user in credential_report:
        username = user["username"]

        active_access_key_ids = active_keys_by_user.get(
            username,
            [],
        )

        results.append(
            {
                "username": username,
                "password_enabled": user[
                    "password_enabled"
                ],
                "active_access_key_count": len(
                    active_access_key_ids
                ),
                "active_access_key_ids": active_access_key_ids,
            }
        )

    return results


def collect_root_access_key(
    collector: IAMDataCollector,
) -> dict[str, Any]:
    """
    Collect root access-key state for IAM-021.

    IAMDataCollector delegates the account-summary reuse to
    IAMService, preventing duplicate AWS GetAccountSummary calls.
    """
    return collector.collect_root_access_key()


def collect_user_attached_policies(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Collect direct IAM-user policy attachments for IAM-022.

    The collector and IAM service reuse their existing per-scan
    caches so this handler does not introduce duplicate AWS API
    calls for policy attachment discovery.
    """
    return collector.collect_user_attached_policies()


def collect_administrative_group_policies(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Collect direct AdministratorAccess attachments for every IAM
    group.

    IAMDataCollector reuses its group and attached-policy caches,
    preventing duplicate AWS API calls during the same scan.
    """
    return collector.collect_administrative_group_policies()


def collect_no_active_authentication_credentials(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Collect authentication-credential state for IAM-020.

    The IAMDataCollector reuses its credential-report and
    access-key caches, so this handler does not introduce
    additional AWS API calls.
    """
    return collector.collect_no_active_authentication_credentials()


def collect_privileged_users_without_boundary(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_privileged_users_without_boundary()


def collect_wildcard_role_trust_principals(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_wildcard_role_trust_principals()


def collect_stale_iam_users(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Collect stale IAM users for IAM-023.

    The collector reuses existing credential-report and access-key
    last-used caches, so this handler does not introduce duplicate
    AWS API calls during the same scan.
    """
    return collector.collect_stale_iam_users()


def collect_access_key_last_used(
    collector: IAMDataCollector,
) -> list[dict[str, Any]]:
    """
    Collect last-used timestamps for active IAM access keys.

    IAMDataCollector caches the AWS GetAccessKeyLastUsed response
    per access key, so repeated rule execution does not introduce
    duplicate AWS API calls during the same scan.
    """
    return collector.collect_access_key_last_used()


IAM_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[IAMDataCollector], Any],
] = {
    "root_mfa": IAMDataCollector.collect_root_mfa,
    "root_access_key": collect_root_access_key,
    "user_attached_policies": (
        collect_user_attached_policies
    ),
    "administrative_group_policies": (
        collect_administrative_group_policies
    ),
    "iam_users": IAMDataCollector.collect_iam_users,
    "iam_access_keys": IAMDataCollector.collect_iam_access_keys,
    "password_policy": IAMDataCollector.collect_password_policy,
    "credential_report": IAMDataCollector.collect_credential_report,
    "broad_user_policies": (
        IAMDataCollector.collect_broad_user_policies
    ),
    "broad_group_policies": (
        IAMDataCollector.collect_broad_group_policies
    ),
    "broad_user_inline_policies": (
        IAMDataCollector.collect_broad_user_inline_policies
    ),
    "broad_group_inline_policies": (
        IAMDataCollector.collect_broad_group_inline_policies
    ),
    "broad_action_restricted_resources": (
        IAMDataCollector.collect_broad_action_restricted_resources
    ),
    "multiple_active_access_keys": (
        collect_multiple_active_access_keys
    ),
    "multiple_authentication_methods": (
        collect_multiple_authentication_methods
    ),
    "no_active_authentication_credentials": (
        collect_no_active_authentication_credentials
    ),
    "stale_iam_users": (
        collect_stale_iam_users
    ),
    "privileged_users_without_boundary": (
        collect_privileged_users_without_boundary
    ),
    "wildcard_role_trust_principals": (
        collect_wildcard_role_trust_principals
    ),
    "access_key_last_used": (
        collect_access_key_last_used
    ),
}
