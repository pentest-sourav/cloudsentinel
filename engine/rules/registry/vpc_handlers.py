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


def collect_client_vpn_logging_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_client_vpn_logging_coverage()


def collect_vpn_logging_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_vpn_logging_coverage()


def collect_spot_fleet_ebs_encryption_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_spot_fleet_ebs_encryption_coverage()


def collect_eni_source_destination_check_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_eni_source_destination_check_coverage()


def collect_vpn_ikev2_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_vpn_ikev2_coverage()



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
    "client_vpn_logging_coverage": (
        collect_client_vpn_logging_coverage
    ),
    "vpn_logging_coverage": collect_vpn_logging_coverage,
    "spot_fleet_ebs_encryption_coverage": (
        collect_spot_fleet_ebs_encryption_coverage
    ),
    "eni_source_destination_check_coverage": (
        collect_eni_source_destination_check_coverage
    ),
    "vpn_ikev2_coverage": collect_vpn_ikev2_coverage,
}


def collect_ec2_eni_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_eni_tagging()


def collect_ec2_igw_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_igw_tagging()


def collect_ec2_nat_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_nat_gateway_tagging()


def collect_ec2_nacl_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_nacl_tagging()


def collect_ec2_route_table_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_route_table_tagging()


def collect_ec2_security_group_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_security_group_tagging()


def collect_ec2_subnet_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_subnet_tagging()


def collect_ec2_vpc_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_vpc_tagging()


def collect_ec2_flow_log_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_flow_log_tagging()


def collect_ec2_vpc_peering_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_vpc_peering_tagging()


def collect_ec2_vpn_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_vpn_gateway_tagging()


def collect_ec2_transit_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_ec2_transit_gateway_tagging()


VPC_DATA_SOURCE_HANDLERS.update(
    {
        "ec2_eni_tagging": collect_ec2_eni_tagging,
        "ec2_igw_tagging": collect_ec2_igw_tagging,
        "ec2_nat_gateway_tagging": (
            collect_ec2_nat_gateway_tagging
        ),
        "ec2_nacl_tagging": collect_ec2_nacl_tagging,
        "ec2_route_table_tagging": (
            collect_ec2_route_table_tagging
        ),
        "ec2_security_group_tagging": (
            collect_ec2_security_group_tagging
        ),
        "ec2_subnet_tagging": collect_ec2_subnet_tagging,
        "ec2_vpc_tagging": collect_ec2_vpc_tagging,
        "ec2_flow_log_tagging": (
            collect_ec2_flow_log_tagging
        ),
        "ec2_vpc_peering_tagging": (
            collect_ec2_vpc_peering_tagging
        ),
        "ec2_vpn_gateway_tagging": (
            collect_ec2_vpn_gateway_tagging
        ),
        "ec2_transit_gateway_tagging": (
            collect_ec2_transit_gateway_tagging
        ),
    }
)
