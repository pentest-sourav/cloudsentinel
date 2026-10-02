from typing import Any

from scanner.aws.services.cloudwatch import CloudWatchService
from scanner.aws.services.cloudtrail import CloudTrailService
from scanner.aws.services.sns import SNSService


CLOUDWATCH_LOG_METRIC_CONTROL_PATTERNS = {
    "1": '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
    "2": '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}',
    "3": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }',
    "4": '{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}',
    "5": '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}',
    "6": '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}',
    "7": '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}',
    "8": '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}',
    "9": '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}',
    "10": '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}',
    "11": '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}',
    "12": '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}',
    "13": '{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}',
    "14": '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}',
}




class CloudWatchDataCollector:
    """
    Normalize Amazon CloudWatch configuration for
    CloudSentinel security rules.

    All AWS API data is cached for the duration of one scan.
    """

    def __init__(
        self,
        service: CloudWatchService,
    ):
        self.service = service

        self._alarms_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._log_groups_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._log_metric_alarm_controls_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_alarms(
        self,
    ) -> list[dict[str, Any]]:
        if self._alarms_cache is None:
            self._alarms_cache = (
                self.service.list_metric_alarms()
            )

        return self._alarms_cache

    def _get_log_groups(
        self,
    ) -> list[dict[str, Any]]:
        if self._log_groups_cache is None:
            self._log_groups_cache = (
                self.service.list_log_groups()
            )

        return self._log_groups_cache

    def collect_alarms(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for alarm in self._get_alarms():
            alarm_name = alarm.get(
                "AlarmName"
            )

            if (
                not isinstance(alarm_name, str)
                or not alarm_name
            ):
                continue

            normalized.append(
                {
                    "resource_id": alarm_name,
                    "resource_type": "cloudwatch_alarm",
                    "alarm_arn": alarm.get(
                        "AlarmArn"
                    ),
                    "alarm_name": alarm_name,
                    "actions_enabled": alarm.get(
                        "ActionsEnabled"
                    ),
                    "alarm_actions": (
                        alarm.get("AlarmActions", [])
                        if isinstance(
                            alarm.get("AlarmActions", []),
                            list,
                        )
                        else []
                    ),
                    "ok_actions": (
                        alarm.get("OKActions", [])
                        if isinstance(
                            alarm.get("OKActions", []),
                            list,
                        )
                        else []
                    ),
                    "insufficient_data_actions": (
                        alarm.get(
                            "InsufficientDataActions",
                            [],
                        )
                        if isinstance(
                            alarm.get(
                                "InsufficientDataActions",
                                [],
                            ),
                            list,
                        )
                        else []
                    ),
                    "state_value": alarm.get(
                        "StateValue"
                    ),
                    "state_reason": alarm.get(
                        "StateReason"
                    ),
                    "metric_name": alarm.get(
                        "MetricName"
                    ),
                    "namespace": alarm.get(
                        "Namespace"
                    ),
                }
            )

        return normalized

    def collect_log_metric_alarm_controls(
        self,
    ) -> list[dict[str, Any]]:
        """
        Evaluate CloudWatch.1 through CloudWatch.14.

        Each control requires the AWS-prescribed metric filter on a
        CloudTrail-backed CloudWatch Logs group, an alarm referencing
        that metric, and an SNS notification action with at least one
        subscription.
        """
        if self._log_metric_alarm_controls_cache is not None:
            return self._log_metric_alarm_controls_cache
        cloudtrail_service = CloudTrailService(
            self.service.session
        )

        sns_services: dict[str, SNSService] = {}
        trails = cloudtrail_service.describe_trails()

        if not trails:
            self._log_metric_alarm_controls_cache = []
            return []

        alarms = self._get_alarms()
        results: dict[str, dict[str, Any]] = {
            control_id: {
                "resource_id": f"cloudwatch-control-{control_id}",
                "control_id": control_id,
                "compliant": False,
                "evidence": {
                    "control_id": control_id,
                    "trail_count": len(trails),
                },
            }
            for control_id in CLOUDWATCH_LOG_METRIC_CONTROL_PATTERNS
        }

        def sns_service_for(topic_arn: str) -> SNSService | None:
            parts = topic_arn.split(":")
            if len(parts) < 4 or not parts[3]:
                return None

            region = parts[3]

            if region not in sns_services:
                sns_services[region] = SNSService(
                    self.service.session,
                    region,
                )

            return sns_services[region]

        def alarm_has_sns_subscription(
            alarm: dict[str, Any],
        ) -> tuple[bool, str | None]:
            actions = alarm.get("AlarmActions", [])

            if not isinstance(actions, list):
                return False, None

            for action in actions:
                if not isinstance(action, str):
                    continue

                if not action.startswith("arn:aws:sns:"):
                    continue

                service = sns_service_for(action)

                if service is None:
                    continue

                subscriptions = (
                    service.list_subscriptions_by_topic(
                        action
                    )
                )

                if subscriptions:
                    return True, action

            return False, None

        for trail in trails:
            log_group_arn = trail.get(
                "CloudWatchLogsLogGroupArn"
            )

            if not isinstance(log_group_arn, str):
                continue

            marker = ":log-group:"
            if marker not in log_group_arn:
                continue

            log_group_name = log_group_arn.split(
                marker,
                1,
            )[1]

            if log_group_name.endswith(":*"):
                log_group_name = log_group_name[:-2]

            filters = (
                self.service.list_metric_filters_for_log_group(
                    log_group_name
                )
            )

            for control_id, expected_pattern in (
                CLOUDWATCH_LOG_METRIC_CONTROL_PATTERNS.items()
            ):
                if results[control_id]["compliant"]:
                    continue

                matching_filter = None

                for metric_filter in filters:
                    if metric_filter.get(
                        "filterPattern"
                    ) != expected_pattern:
                        continue

                    transformations = metric_filter.get(
                        "metricTransformations",
                        [],
                    )

                    if not isinstance(
                        transformations,
                        list,
                    ):
                        continue

                    for transformation in transformations:
                        if not isinstance(
                            transformation,
                            dict,
                        ):
                            continue

                        if (
                            transformation.get(
                                "metricNamespace"
                            )
                            != "LogMetrics"
                        ):
                            continue

                        if str(
                            transformation.get(
                                "metricValue"
                            )
                        ) != "1":
                            continue

                        if str(
                            transformation.get(
                                "defaultValue"
                            )
                        ) != "0":
                            continue

                        matching_filter = {
                            "filter_name": metric_filter.get(
                                "filterName"
                            ),
                            "filter_pattern": expected_pattern,
                            "metric_name": transformation.get(
                                "metricName"
                            ),
                            "metric_namespace": transformation.get(
                                "metricNamespace"
                            ),
                        }
                        break

                    if matching_filter:
                        break

                if not matching_filter:
                    continue

                metric_name = matching_filter.get(
                    "metric_name"
                )

                for alarm in alarms:
                    if (
                        alarm.get("MetricName")
                        != metric_name
                    ):
                        continue

                    if (
                        alarm.get("Namespace")
                        != "LogMetrics"
                    ):
                        continue

                    if (
                        alarm.get("ComparisonOperator")
                        != "GreaterThanOrEqualToThreshold"
                    ):
                        continue

                    threshold = alarm.get("Threshold")

                    if not isinstance(
                        threshold,
                        (int, float),
                    ) or isinstance(threshold, bool):
                        continue

                    if threshold < 1:
                        continue

                    has_subscription, sns_topic = (
                        alarm_has_sns_subscription(alarm)
                    )

                    if not has_subscription:
                        continue

                    results[control_id] = {
                        "resource_id": (
                            alarm.get("AlarmName")
                            or f"cloudwatch-control-{control_id}"
                        ),
                        "control_id": control_id,
                        "compliant": True,
                        "evidence": {
                            "control_id": control_id,
                            "trail_arn": trail.get(
                                "TrailARN"
                            ),
                            "log_group_arn": log_group_arn,
                            "log_group_name": log_group_name,
                            "metric_filter": matching_filter,
                            "alarm_name": alarm.get(
                                "AlarmName"
                            ),
                            "alarm_arn": alarm.get(
                                "AlarmArn"
                            ),
                            "alarm_threshold": threshold,
                            "sns_topic_arn": sns_topic,
                        },
                    }
                    break

        collected = list(results.values())
        self._log_metric_alarm_controls_cache = collected
        return collected


    def collect_log_groups(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for log_group in self._get_log_groups():
            name = log_group.get(
                "logGroupName"
            )

            if (
                not isinstance(name, str)
                or not name
            ):
                continue

            retention = log_group.get(
                "retentionInDays"
            )

            normalized.append(
                {
                    "resource_id": name,
                    "resource_type": "cloudwatch_log_group",
                    "log_group_name": name,
                    "retention_in_days": retention,
                    "stored_bytes": log_group.get(
                        "storedBytes"
                    ),
                    "creation_time": log_group.get(
                        "creationTime"
                    ),
                    "arn": log_group.get(
                        "arn"
                    ),
                }
            )

        return normalized
