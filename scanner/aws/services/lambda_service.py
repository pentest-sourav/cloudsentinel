from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class LambdaService:
    """
    Read-only AWS Lambda discovery service.

    This service is responsible only for collecting Lambda
    configuration data from AWS. Security evaluation is
    handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.lambda_client = create_aws_client(session, "lambda")
        self._ec2_client = None

    def list_functions(self) -> list[dict[str, Any]]:
        try:
            paginator = self.lambda_client.get_paginator("list_functions")

            functions = []

            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))

            return functions

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda function discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda function discovery: {exc}"
            ) from exc

    def get_function_url_config(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        try:
            response = self.lambda_client.get_function_url_config(
                FunctionName=function_name
            )

            return {
                "function_url": response.get("FunctionUrl"),
                "auth_type": response.get("AuthType"),
                "creation_time": response.get("CreationTime"),
                "last_modified_time": response.get("LastModifiedTime"),
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda function URL discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda function URL discovery: "
                f"{exc}"
            ) from exc

    def get_function_policy(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve the Lambda function resource-based policy.

        AWS returns the policy document as a JSON string. The service
        normalizes it into a Python dictionary so collectors and rules
        do not need to understand the raw Lambda API response format.

        A function without a resource-based policy returns None.
        """
        try:
            response = self.lambda_client.get_policy(
                FunctionName=function_name
            )

            policy_document = response.get("Policy")

            if not policy_document:
                return None

            if isinstance(policy_document, str):
                import json

                policy_document = json.loads(policy_document)

            return {
                "policy": policy_document,
                "revision_id": response.get("RevisionId"),
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda function policy discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda function policy discovery: "
                f"{exc}"
            ) from exc

    def get_function_code_signing_config(
        self,
        function_name: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve the Code Signing Configuration associated with a
        Lambda function.

        Functions without a Code Signing Configuration return None.
        """
        try:
            response = self.lambda_client.get_function_code_signing_config(
                FunctionName=function_name
            )

            code_signing_config_arn = response.get("CodeSigningConfigArn")

            if not code_signing_config_arn:
                return None

            return {
                "code_signing_config_arn": code_signing_config_arn,
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda code-signing configuration discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda code-signing configuration "
                f"discovery: {exc}"
            ) from exc

    def get_code_signing_config(
        self,
        code_signing_config_arn: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve the enforcement policy for a Lambda Code Signing
        Configuration.
        """
        try:
            response = self.lambda_client.get_code_signing_config(
                CodeSigningConfigArn=code_signing_config_arn
            )

            code_signing_config = response.get("CodeSigningConfig")

            if not code_signing_config:
                return None

            return {
                "code_signing_config_arn": code_signing_config.get(
                    "CodeSigningConfigArn"
                ),
                "description": code_signing_config.get("Description"),
                "allowed_publishers": code_signing_config.get(
                    "AllowedPublishers"
                ),
                "code_signing_policies": code_signing_config.get(
                    "CodeSigningPolicies"
                ),
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda code-signing configuration retrieval failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda code-signing configuration "
                f"retrieval: {exc}"
            ) from exc

    def list_event_source_mappings(
        self,
        function_name: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve event source mappings for a Lambda function.

        These mappings are used by security rules that need to account
        for event-source-specific Lambda behavior, such as X-Ray
        unsupported event sources.
        """
        try:
            paginator = self.lambda_client.get_paginator(
                "list_event_source_mappings"
            )

            mappings = []

            for page in paginator.paginate(
                FunctionName=function_name
            ):
                mappings.extend(
                    page.get("EventSourceMappings", [])
                )

            return mappings

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda event source mapping discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda event source mapping "
                f"discovery: {exc}"
            ) from exc

    def get_subnet_availability_zones(
        self,
        subnet_ids: list[str],
    ) -> dict[str, str]:
        """
        Resolve Lambda VPC subnet IDs to Availability Zones.

        Lambda VpcConfig contains subnet IDs but not their AZ names,
        so the EC2 DescribeSubnets API is used for the enrichment.
        """
        if not subnet_ids:
            return {}

        if self._ec2_client is None:
            self._ec2_client = create_aws_client(
                self.session,
                "ec2",
            )

        try:
            response = self._ec2_client.describe_subnets(
                SubnetIds=subnet_ids
            )

            return {
                subnet.get("SubnetId"): subnet.get("AvailabilityZone")
                for subnet in response.get("Subnets", [])
                if subnet.get("SubnetId")
                and subnet.get("AvailabilityZone")
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Lambda subnet availability-zone discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Lambda subnet "
                f"availability-zone discovery: {exc}"
            ) from exc
