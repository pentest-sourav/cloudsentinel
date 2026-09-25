from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SESService:
    """
    Read-only Amazon SES v2 discovery service.

    Retrieves contact lists and configuration sets together
    with their security-relevant metadata.
    """

    def __init__(self, session):
        self.session = session
        self.ses_client = create_aws_client(
            session,
            "sesv2",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SES {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during SES "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during SES "
            f"{operation}: {exc}"
        ) from exc

    def list_contact_lists(
        self,
    ) -> list[dict[str, Any]]:
        try:
            contact_lists: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "PageSize": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.ses_client.list_contact_lists(
                        **request
                    )
                )

                entries = response.get(
                    "ContactLists",
                    [],
                )

                if isinstance(entries, list):
                    contact_lists.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return contact_lists

        except Exception as exc:
            self._raise_api_error(
                "contact-list discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_contact_list(
        self,
        contact_list_name: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.ses_client.get_contact_list(
                    ContactListName=contact_list_name,
                )
            )

            return (
                response
                if isinstance(response, dict)
                else {}
            )

        except Exception as exc:
            self._raise_api_error(
                "contact-list metadata discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_configuration_sets(
        self,
    ) -> list[str]:
        try:
            configuration_sets: list[str] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "PageSize": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.ses_client
                    .list_configuration_sets(
                        **request
                    )
                )

                entries = response.get(
                    "ConfigurationSets",
                    [],
                )

                if isinstance(entries, list):
                    configuration_sets.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, str)
                        and entry
                    )

                token = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return configuration_sets

        except Exception as exc:
            self._raise_api_error(
                "configuration-set discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_configuration_set(
        self,
        configuration_set_name: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.ses_client.get_configuration_set(
                    ConfigurationSetName=(
                        configuration_set_name
                    ),
                )
            )

            return (
                response
                if isinstance(response, dict)
                else {}
            )

        except Exception as exc:
            self._raise_api_error(
                "configuration-set metadata discovery",
                exc,
            )
            raise AssertionError("unreachable")
