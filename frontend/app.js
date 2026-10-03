              )}.`
            : `Scan #${scan?.id || "—"} is ${status}.`;

    $("latest-scan").innerHTML = `
        <div class="latest-scan-detail">

            <div class="latest-scan-top">

                <div>

                    <div class="latest-scan-id">
                        Scan #${escapeHtml(
                            scan?.id
                        )}
                    </div>

                    <div class="latest-scan-meta">

                        <span class="status ${escapeHtml(
                            status
                        )}">
                            ${escapeHtml(
                                scan?.status ||
                                "unknown"
                            )}
                        </span>

                        <span class="status">
                            ${escapeHtml(
                                scan?.provider ||
                                "aws"
                            )}
                        </span>

                        <span class="status">
                            ${formatDate(
                                scan?.completed_at
                            )}
                        </span>

                    </div>

                </div>

                <button
                    class="secondary-btn"
                    type="button"
                    data-open-scan="${scan?.id}"
                >
                    Investigate
                </button>

            </div>


            ${scan?.progress && status === "running" ? `
                <div class="scan-progress-block">
                    <div class="scan-progress-header">
                        <span>Live scan progress</span>
                        <strong>${safeNumber(scan.progress.percent)}%</strong>
                    </div>
                    <progress class="scan-progress-meter" max="100" value="${safeNumber(scan.progress.percent)}"></progress>
                    <div class="scan-progress-meta">
                        <span>${escapeHtml(scan.progress.service || "Scanning")}</span>
                        <span>${escapeHtml(scan.progress.region || "global")}</span>
                    </div>
                </div>
            ` : ""}

            <div class="latest-scan-stats">

                <div class="latest-mini-stat">
                    <span>Total</span>
                    <strong>
                        ${total}
                    </strong>
                </div>

                <div class="latest-mini-stat">
                    <span>Critical</span>
                    <strong class="critical">
                        ${critical}
                    </strong>
                </div>

                <div class="latest-mini-stat">
                    <span>High</span>
                    <strong class="high">
                        ${high}
                    </strong>
                </div>

                <div class="latest-mini-stat">
                    <span>Errors</span>
                    <strong>
                        ${safeNumber(
                            summary?.execution_error_count
                        )}
                    </strong>
                </div>

            </div>

        </div>
    `;
}

function renderRiskRing({
    critical,
    high,
    medium,
    low,
    info,
    total,
}) {
    const ring =
        $("risk-ring");

    if (!total) {
        ring.style.background =
            "conic-gradient(#18283d 0deg 360deg)";

        return;
    }

    const values = [
        [critical, "var(--critical)"],
        [high, "var(--high)"],
        [medium, "var(--medium)"],
        [low, "var(--low)"],
        [info, "var(--info)"],
    ];

    let cursor = 0;
