from typing import Any, Callable

from scanner.aws.collectors.s3 import S3DataCollector


S3_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[S3DataCollector], Any],
] = {
    "s3_public_access": S3DataCollector.collect_public_access,
    "s3_encryption": S3DataCollector.collect_encryption,
    "s3_bucket_policy": S3DataCollector.collect_bucket_policy,
    "s3_tls_policy": S3DataCollector.collect_tls_policy,
    "s3_acl": S3DataCollector.collect_acl,
    "s3_versioning": S3DataCollector.collect_versioning,
    "s3_logging": S3DataCollector.collect_logging,
    "s3_object_lock": S3DataCollector.collect_object_lock,
    "s3_ownership": S3DataCollector.collect_ownership,
}
