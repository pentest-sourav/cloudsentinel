from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderIdentity:
    provider: str
    account_id: str
    display_name: str | None = None


class CloudProvider(ABC):
    """
    Common interface for all cloud providers.

    Provider implementations must expose a safe,
    read-only identity verification method.
    """

    provider_name: str

    @abstractmethod
    def verify_identity(self) -> ProviderIdentity:
        """
        Verify that the configured credentials can access
        the cloud account and return its identity.
        """
        raise NotImplementedError
