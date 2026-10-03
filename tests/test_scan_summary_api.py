            provider="aws",
            resource_type="test_resource",
            resource_id="resource-medium-1",
            description="Medium test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
        Finding(
            scan_id=scan.id,
            rule_id="TEST-MEDIUM-2",
            title="Medium Test Finding 2",
            severity="medium",
            risk_score=5.0,
            risk_level="medium",
            provider="aws",
            resource_type="test_resource",
            resource_id="resource-medium-2",
            description="Medium test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
    ]

    db.add_all(findings)
    db.commit()

    scan_id = scan.id
    user_email = user.email
    db.close()

    return scan_id, user_email


def test_get_scan_summary(client):
    scan_id, email = setup_scan_with_findings()

    token = login(client, email)

    response = client.get(
        f"/api/v1/scans/{scan_id}/summary",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == scan_id
    assert data["provider"] == "aws"
    assert data["status"] == "completed"

    assert data["total_findings"] == 4
    assert data["critical_count"] == 1
    assert data["high_count"] == 1
    assert data["medium_count"] == 2
    assert data["low_count"] == 0
    assert data["info_count"] == 0

    assert data["risk_posture"]["score"] == 40.0
    assert data["risk_posture"]["grade"] == "F"
    assert data["risk_posture"]["average_risk_score"] == 6.5
    assert data["risk_posture"]["max_risk_score"] == 9.0
    assert data["risk_posture"]["risk_score_sum"] == 26.0
    assert data["risk_posture"]["affected_resource_count"] == 4
    assert len(data["risk_posture"]["top_risks"]) == 4
    assert data["risk_posture"]["top_risks"][0]["rule_id"] == "TEST-CRITICAL"


def test_get_scan_summary_returns_404_for_unknown_scan(client):
    create_test_user()

    token = login(
        client,
        "summary-owner@example.com",
    )

    response = client.get(
        "/api/v1/scans/99999/summary",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Scan not found",
    }


def test_get_scan_summary_returns_zero_counts_when_no_findings(client):
    user = create_test_user(
        email="empty-summary@example.com",
        tenant_name="Empty Summary Tenant",
        tenant_slug="empty-summary-tenant",
    )

    db = TestingSessionLocal()

    scan = Scan(