CLOUD_ACCOUNT_PENDING = "pending_connection"
CLOUD_ACCOUNT_CONNECTED = "connected"
CLOUD_ACCOUNT_CONNECTION_FAILED = "connection_failed"

# Backward compatibility for accounts created before the SaaS
# connection lifecycle was introduced.
LEGACY_CONNECTED_STATUS = "active"

SCAN_ELIGIBLE_ACCOUNT_STATUSES = frozenset(
    {
        CLOUD_ACCOUNT_CONNECTED,
        LEGACY_CONNECTED_STATUS,
    }
)
