from scanner.aws.collectors.ses import SESDataCollector


def collect_ses_contact_lists(
    collector: SESDataCollector,
) -> list[dict]:
    return collector.collect_contact_lists()


def collect_ses_configuration_sets(
    collector: SESDataCollector,
) -> list[dict]:
    return collector.collect_configuration_sets()


SES_DATA_SOURCE_HANDLERS = {
    "ses_contact_lists": collect_ses_contact_lists,
    "ses_configuration_sets": collect_ses_configuration_sets,
}
