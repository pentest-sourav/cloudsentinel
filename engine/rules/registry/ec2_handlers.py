from functools import partial
from typing import Any

from scanner.aws.collectors.ec2 import EC2DataCollector
from scanner.aws.collectors.security_group_rules import (
    SecurityGroupRuleCollector,
)


def collect_ec2_security_group_rules(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    security_groups = collector.collect_security_groups()

    rule_collector = SecurityGroupRuleCollector()

    return rule_collector.collect(security_groups)


def collect_ec2_instances(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_instances()


def collect_ec2_extended_instances(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_extended_instances()


def collect_ec2_ebs_volumes(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_ebs_volumes()


def collect_ec2_snapshots(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_snapshots()


def collect_ec2_ebs_default_encryption(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_ebs_default_encryption()


def collect_ec2_elastic_ips(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_elastic_ips()


def collect_ec2_launch_template_ebs_encryption(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_launch_template_ebs_encryption()


def collect_ec2_snapshot_block_public_access(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_snapshot_block_public_access()


def _ec2_tagging_collector(
    collector: EC2DataCollector,
):
    from scanner.aws.collectors.ec2_tagging import (
        EC2TaggingDataCollector,
    )

    return EC2TaggingDataCollector(
        collector.service
    )


def collect_ec2_instance_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_instances()


def collect_ec2_network_interface_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_network_interfaces()


def collect_ec2_security_group_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_security_groups()


def collect_ec2_volume_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_volumes()


def collect_ec2_elastic_ip_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_elastic_ips()


def collect_ec2_vpc_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_vpcs()


def collect_ec2_subnet_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_subnets()


def collect_ec2_internet_gateway_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_internet_gateways()


def collect_ec2_nat_gateway_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_nat_gateways()


def collect_ec2_network_acl_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_network_acls()


def collect_ec2_route_table_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_route_tables()


def collect_ec2_flow_log_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_flow_logs()


def collect_ec2_vpc_peering_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_vpc_peering_connections()


def collect_ec2_vpn_gateway_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_vpn_gateways()


def collect_ec2_transit_gateway_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(
        collector
    ).collect_transit_gateways()


# ---------------------------------------------------------------------------
# Extended EC2 Security Hub collectors
# ---------------------------------------------------------------------------

def collect_ec2_vpn_connections(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_vpn_connections()


def collect_ec2_transit_gateway_options(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_transit_gateway_options()


def collect_ec2_launch_template_network_interfaces(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_launch_template_network_interfaces()


def collect_ec2_launch_template_imdsv2(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_launch_template_imdsv2()


def collect_ec2_remote_admin_rules(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    # EC2.53 / EC2.54 use the same normalized security-group rule
    # source as the existing EC2 security-group exposure control.
    return collect_ec2_security_group_rules(collector)


def collect_ec2_transit_gateway_attachment_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_transit_gateway_attachments()


def collect_ec2_transit_gateway_route_table_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_transit_gateway_route_tables()


def collect_ec2_customer_gateway_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_customer_gateways()


def collect_ec2_vpc_endpoint_service_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_vpc_endpoint_services()


def collect_ec2_dhcp_options_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_dhcp_options()


def collect_ec2_launch_template_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_launch_templates()


def collect_ec2_prefix_list_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_prefix_lists()


def collect_ec2_traffic_mirror_session_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_traffic_mirror_sessions()


def collect_ec2_traffic_mirror_filter_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_traffic_mirror_filters()


def collect_ec2_traffic_mirror_target_tagging(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return _ec2_tagging_collector(collector).collect_traffic_mirror_targets()


EC2_DATA_SOURCE_HANDLERS = {
    "ec2_security_group_rules": collect_ec2_security_group_rules,
    "ec2_instances": collect_ec2_instances,
    "ec2_extended_instances": collect_ec2_extended_instances,
    "ec2_ebs_volumes": collect_ec2_ebs_volumes,
    "ec2_snapshots": collect_ec2_snapshots,
    "ec2_ebs_default_encryption": (
        collect_ec2_ebs_default_encryption
    ),
    "ec2_elastic_ips": collect_ec2_elastic_ips,
    "ec2_launch_template_ebs_encryption": (
        collect_ec2_launch_template_ebs_encryption
    ),
    "ec2_snapshot_block_public_access": (
        collect_ec2_snapshot_block_public_access
    ),

    "ec2_vpn_connections": collect_ec2_vpn_connections,
    "ec2_transit_gateway_options": collect_ec2_transit_gateway_options,
    "ec2_launch_template_network_interfaces": (
        collect_ec2_launch_template_network_interfaces
    ),
    "ec2_launch_template_imdsv2": collect_ec2_launch_template_imdsv2,
    "ec2_remote_admin_rules": collect_ec2_remote_admin_rules,

    "ec2_transit_gateway_attachment_tagging": (
        collect_ec2_transit_gateway_attachment_tagging
    ),
    "ec2_transit_gateway_route_table_tagging": (
        collect_ec2_transit_gateway_route_table_tagging
    ),
    "ec2_customer_gateway_tagging": (
        collect_ec2_customer_gateway_tagging
    ),
    "ec2_vpc_endpoint_service_tagging": (
        collect_ec2_vpc_endpoint_service_tagging
    ),
    "ec2_dhcp_options_tagging": collect_ec2_dhcp_options_tagging,
    "ec2_launch_template_tagging": collect_ec2_launch_template_tagging,
    "ec2_prefix_list_tagging": collect_ec2_prefix_list_tagging,
    "ec2_traffic_mirror_session_tagging": (
        collect_ec2_traffic_mirror_session_tagging
    ),
    "ec2_traffic_mirror_filter_tagging": (
        collect_ec2_traffic_mirror_filter_tagging
    ),
    "ec2_traffic_mirror_target_tagging": (
        collect_ec2_traffic_mirror_target_tagging
    ),

    "ec2_instance_tagging": collect_ec2_instance_tagging,
    "ec2_network_interface_tagging": (
        collect_ec2_network_interface_tagging
    ),
    "ec2_security_group_tagging": (
        collect_ec2_security_group_tagging
    ),
    "ec2_volume_tagging": collect_ec2_volume_tagging,
    "ec2_elastic_ip_tagging": (
        collect_ec2_elastic_ip_tagging
    ),
    "ec2_vpc_tagging": collect_ec2_vpc_tagging,
    "ec2_subnet_tagging": collect_ec2_subnet_tagging,
    "ec2_internet_gateway_tagging": (
        collect_ec2_internet_gateway_tagging
    ),
    "ec2_nat_gateway_tagging": (
        collect_ec2_nat_gateway_tagging
    ),
    "ec2_network_acl_tagging": (
        collect_ec2_network_acl_tagging
    ),
    "ec2_route_table_tagging": (
        collect_ec2_route_table_tagging
    ),
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
