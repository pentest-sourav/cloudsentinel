from scanner.aws.collectors.vpc import VPCDataCollector


def collect_vpcs(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_vpcs()


def collect_internet_gateways(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_internet_gateways()


def collect_default_security_groups(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_default_security_groups()


def collect_flow_log_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_flow_log_coverage()


def collect_ec2_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_endpoint_coverage()


def collect_vpc_block_public_access_options(
    collector: VPCDataCollector,
) -> dict:
    return collector.collect_vpc_block_public_access_options()


def collect_subnet_public_ip_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_subnet_public_ip_coverage()


def collect_unused_network_acl_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_unused_network_acl_coverage()


def collect_ecr_api_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_required_endpoint_coverage(
        "com.amazonaws."
        + str(
            getattr(
                collector.service.ec2_client.meta,
                "region_name",
                "",
            )
        )
        + ".ecr.api"
    )


def collect_ecr_dkr_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_required_endpoint_coverage(
        "com.amazonaws."
        + str(
            getattr(
                collector.service.ec2_client.meta,
                "region_name",
                "",
            )
        )
        + ".ecr.dkr"
    )


def collect_ssm_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_required_endpoint_coverage(
        "com.amazonaws."
        + str(
            getattr(
                collector.service.ec2_client.meta,
                "region_name",
                "",
            )
        )
        + ".ssm"
    )


def collect_ssm_contacts_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_required_endpoint_coverage(
        "com.amazonaws."
        + str(
            getattr(
                collector.service.ec2_client.meta,
                "region_name",
                "",
            )
        )
        + ".ssm-contacts"
    )


def collect_ssm_incidents_endpoint_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_required_endpoint_coverage(
        "com.amazonaws."
        + str(
            getattr(
                collector.service.ec2_client.meta,
                "region_name",
                "",
            )
        )
        + ".ssm-incidents"
    )


def collect_network_acls(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_network_acls()


VPC_DATA_SOURCE_HANDLERS = {
    "vpcs": collect_vpcs,
    "internet_gateways": collect_internet_gateways,
    "default_security_groups": collect_default_security_groups,
    "flow_log_coverage": collect_flow_log_coverage,
    "subnet_public_ip_coverage": collect_subnet_public_ip_coverage,
    "unused_network_acl_coverage": collect_unused_network_acl_coverage,
    "ecr_api_endpoint_coverage": collect_ecr_api_endpoint_coverage,
    "ecr_dkr_endpoint_coverage": collect_ecr_dkr_endpoint_coverage,
    "ssm_endpoint_coverage": collect_ssm_endpoint_coverage,
    "ssm_contacts_endpoint_coverage": collect_ssm_contacts_endpoint_coverage,
    "ssm_incidents_endpoint_coverage": collect_ssm_incidents_endpoint_coverage,
    "vpc_block_public_access_options": (
        collect_vpc_block_public_access_options
    ),
    "network_acls": collect_network_acls,
    "ec2_endpoint_coverage": collect_ec2_endpoint_coverage,
}
