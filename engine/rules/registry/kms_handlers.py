from scanner.aws.collectors.kms import KMSDataCollector


def collect_kms_keys(
    collector: KMSDataCollector,
) -> list[dict]:
    return collector.collect_keys()


KMS_DATA_SOURCE_HANDLERS = {
    "kms_keys": collect_kms_keys,
}
