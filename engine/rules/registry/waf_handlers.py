from scanner.aws.collectors.waf import WAFDataCollector


def collect_waf_web_acls(
    collector: WAFDataCollector,
) -> list[dict]:
    return collector.collect_web_acls()


def collect_waf_rule_groups(
    collector: WAFDataCollector,
) -> list[dict]:
    return collector.collect_rule_groups()


WAF_DATA_SOURCE_HANDLERS = {
    "waf_web_acls": collect_waf_web_acls,
    "waf_rule_groups": collect_waf_rule_groups,
}
