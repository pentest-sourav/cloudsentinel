from typing import Any, Callable

from scanner.aws.collectors.iam import IAMDataCollector


IAM_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[IAMDataCollector], Any],
] = {
    "root_mfa": IAMDataCollector.collect_root_mfa,
    "iam_users": IAMDataCollector.collect_iam_users,
    "iam_access_keys": IAMDataCollector.collect_iam_access_keys,
}
