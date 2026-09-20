from typing import Any, Callable

from scanner.aws.collectors.iam import IAMDataCollector


IAM_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[IAMDataCollector], Any],
] = {
    "root_mfa": IAMDataCollector.collect_root_mfa,
    "iam_users": IAMDataCollector.collect_iam_users,
    "iam_access_keys": IAMDataCollector.collect_iam_access_keys,
    "password_policy": IAMDataCollector.collect_password_policy,
    "credential_report": IAMDataCollector.collect_credential_report,
    "broad_user_policies": IAMDataCollector.collect_broad_user_policies,
    "broad_group_policies": IAMDataCollector.collect_broad_group_policies,
    "broad_user_inline_policies": (
        IAMDataCollector.collect_broad_user_inline_policies
    ),
    "broad_group_inline_policies": (
        IAMDataCollector.collect_broad_group_inline_policies
    ),
}
