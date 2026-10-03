import pytest

from backend.app.services.alert_policy_service import _validate_endpoint


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/webhook",
        "https://example.com:8443/webhook",
        "https://user:password@example.com/webhook",
        "https://127.0.0.1/webhook",
        "https://10.0.0.10/webhook",
        "https://[::1]/webhook",
    ],
)
def test_alert_endpoint_validation_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        _validate_endpoint(url)


def test_alert_endpoint_validation_accepts_https_port_443():
    assert (
        _validate_endpoint("https://example.com/webhook")
        == "https://example.com/webhook"
    )


def test_alert_endpoint_validation_rejects_dns_private_addresses(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                2,
                1,
                6,
                "",
                ("192.168.10.20", 443),
            )
        ]

    monkeypatch.setattr(
        "backend.app.services.alert_policy_service.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(ValueError, match="Private or non-routable"):
        _validate_endpoint("https://webhook.example.com/events")
