const API = "/api/v1";

const state = {
    token: localStorage.getItem("cloudsentinel_token"),
    user: null,
    scans: [],
    accounts: [],
    currentScanId: null,
    currentView: "dashboard",
    pollTimer: null,
};


const $ = (id) => document.getElementById(id);


function escapeHtml(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}


function showToast(message, type = "info") {
    const container = $("toast-container");

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}


function showAuthError(message) {
    const box = $("auth-error");

    box.textContent = message;
    box.classList.remove("hidden");
}


function clearAuthError() {
    $("auth-error").classList.add("hidden");
}


function setToken(token) {
    state.token = token;

    if (token) {
        localStorage.setItem("cloudsentinel_token", token);
    } else {
        localStorage.removeItem("cloudsentinel_token");
    }
}


async function apiFetch(path, options = {}) {
    const headers = {
        ...(options.headers || {}),
    };

    if (state.token) {
        headers.Authorization = `Bearer ${state.token}`;
    }

    if (
        options.body &&
        !(options.body instanceof FormData)
    ) {
        headers["Content-Type"] = "application/json";
    }

    const response = await fetch(`${API}${path}`, {
        ...options,
        headers,
    });

    if (response.status === 401) {
        logout(false);
        throw new Error("Your session has expired.");
    }

    const contentType =
        response.headers.get("content-type") || "";

    let payload;

    if (contentType.includes("application/json")) {
        payload = await response.json();
    } else {
        payload = await response.text();
    }

    if (!response.ok) {
        let message = `Request failed (${response.status})`;

        if (payload && typeof payload === "object") {
            message =
                payload.detail ||
                payload.message ||
                message;
        } else if (payload) {
            message = payload;
        }

        throw new Error(message);
    }

    return payload;
}


function showAuth() {
    $("auth-screen").classList.remove("hidden");
    $("app-screen").classList.add("hidden");
}


function showApp() {
    $("auth-screen").classList.add("hidden");
    $("app-screen").classList.remove("hidden");

    if (state.user) {
        $("current-user").innerHTML = `
            <strong>${escapeHtml(
                state.user.full_name || state.user.email
            )}</strong>
            <span>${escapeHtml(state.user.email)}</span>
        `;
    }
}


async function loadCurrentUser() {
    try {
        const response = await apiFetch("/auth/me");
        state.user = response;
        showApp();
        await loadDashboard();
    } catch {
        /*
         * The current backend does not expose /auth/me in every
         * deployment. Dashboard APIs remain the source of truth.
         */
        showApp();

        try {
            await loadDashboard();
        } catch {
            showAuth();
        }
    }
}


async function login(
    email,
    password,
    tenantName = ""
) {
    clearAuthError();

    const result = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({
            email,
            password,
            tenant_name: tenantName || undefined,
        }),
    });

    setToken(result.access_token);

    /*
     * Login response intentionally contains token metadata only.
     * The UI does not trust client-supplied identity information.
     */
    state.user = {
        email,
    };

    showApp();
    await loadDashboard();
}


async function register(
    fullName,
    tenantName,
    email,
    password
) {
    clearAuthError();

    await apiFetch("/auth/register", {
        method: "POST",
        body: JSON.stringify({
            full_name: fullName,
            tenant_name: tenantName,
            email,
            password,
        }),
    });

    await login(
        email,
        password,
        tenantName
    );
}


function logout(showMessage = true) {
    clearInterval(state.pollTimer);

    setToken(null);
    state.user = null;
    state.currentScanId = null;

    showAuth();

    if (showMessage) {
        showToast("Signed out.", "info");
    }
}


function setView(view) {
    state.currentView = view;

    document
        .querySelectorAll(".view")
        .forEach((element) => {
            element.classList.add("hidden");
        });

    const target = $(`view-${view}`);

    if (target) {
        target.classList.remove("hidden");
    }

    document
        .querySelectorAll(".nav-item")
        .forEach((button) => {
            button.classList.toggle(
                "active",
                button.dataset.view === view
            );
        });

    const titles = {
        dashboard: [
            "Security Dashboard",
            "Monitor cloud security posture and compliance.",
        ],
        accounts: [
            "AWS Accounts",
            "Manage cloud accounts used for security assessments.",
        ],
        scans: [
            "Scan History",
            "Review previous security assessments.",
        ],
        findings: [
            "Security Findings",
            "Investigate detected cloud security issues.",
        ],
        "finding-detail": [
            "Finding Detail",
            "Evidence, remediation and compliance context.",
        ],
        lifecycle: [
            "Finding Lifecycle",
            "Track findings across security scans.",
        ],
    };

    const title = titles[view] || titles.dashboard;

    $("page-title").textContent = title[0];
    $("page-subtitle").textContent = title[1];
}


async function loadAccounts() {
    state.accounts = await apiFetch("/cloud-accounts");

    renderAccounts();
}


function renderAccounts() {
    const body = $("accounts-body");

    if (!state.accounts.length) {
        body.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    No AWS accounts configured.
                </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = state.accounts
        .map((account) => `
            <tr>
                <td>
                    <strong>${escapeHtml(account.name)}</strong>
                </td>
                <td>${escapeHtml(account.provider)}</td>
                <td class="mono">
                    ${escapeHtml(account.external_account_id || "—")}
                </td>
                <td>${escapeHtml(account.region || "—")}</td>
                <td>
                    <span class="status ${escapeHtml(account.status)}">
                        ${escapeHtml(account.status)}
                    </span>
                </td>
                <td>${formatDate(account.created_at)}</td>
            </tr>
        `)
        .join("");
}


async function createAccount(event) {
    event.preventDefault();

    try {
        await apiFetch("/cloud-accounts", {
            method: "POST",
            body: JSON.stringify({
                name: $("account-name").value.trim(),
                provider: "aws",
                external_account_id:
                    $("account-id").value.trim() || null,
                role_arn:
                    $("role-arn").value.trim() || null,
                external_id:
                    $("external-id").value.trim() || null,
                region:
                    $("account-region").value.trim() || null,
            }),
        });

        $("account-form").reset();
        $("account-region").value = "us-east-1";
        $("account-form-container").classList.add("hidden");

        await loadAccounts();

        showToast(
            "AWS account added successfully.",
            "success"
        );
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function loadScans() {
    const result = await apiFetch(
        "/scans?limit=50&offset=0"
    );

    state.scans = result.items || [];

    renderRecentScans();
    renderHistory();

    return result;
}


function statusBadge(status) {
    const normalized = String(status || "").toLowerCase();

    return `
        <span class="status ${escapeHtml(normalized)}">
            ${escapeHtml(status)}
        </span>
    `;
}


function renderRecentScans() {
    const body = $("recent-scans-body");

    if (!state.scans.length) {
        body.innerHTML = `
            <tr>
                <td colspan="8" class="empty-state">
                    No scans have been run yet.
                </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = state.scans
        .slice(0, 10)
        .map((scan) => `
            <tr>
                <td>
                    <button
                        class="link-btn"
                        onclick="openScan(${scan.id})"
                    >
                        #${scan.id}
                    </button>
                </td>
                <td>${escapeHtml(scan.provider)}</td>
                <td>${statusBadge(scan.status)}</td>
                <td>${scan.total_findings}</td>
                <td>${scan.critical_count}</td>
                <td>${scan.high_count}</td>
                <td>${formatDate(scan.completed_at)}</td>
                <td>
                    <button
                        class="secondary-btn tiny"
                        onclick="openScan(${scan.id})"
                    >
                        View
                    </button>
                </td>
            </tr>
        `)
        .join("");
}


function renderHistory() {
    const body = $("history-body");

    if (!state.scans.length) {
        body.innerHTML = `
            <tr>
                <td colspan="10" class="empty-state">
                    No scan history available.
                </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = state.scans
        .map((scan) => `
            <tr>
                <td>
                    <button
                        class="link-btn"
                        onclick="openScan(${scan.id})"
                    >
                        #${scan.id}
                    </button>
                </td>
                <td>${escapeHtml(scan.provider)}</td>
                <td>${statusBadge(scan.status)}</td>
                <td>${scan.total_findings}</td>
                <td>${scan.critical_count}</td>
                <td>${scan.high_count}</td>
                <td>${scan.medium_count}</td>
                <td>${scan.low_count}</td>
                <td>${formatDate(scan.completed_at)}</td>
                <td>
                    <button
                        class="secondary-btn tiny"
                        onclick="openScan(${scan.id})"
                    >
                        View
                    </button>
                </td>
            </tr>
        `)
        .join("");
}


function updateDashboardStats(summary) {
    $("stat-total").textContent =
        summary.total_findings ?? 0;

    $("stat-critical").textContent =
        summary.critical_count ?? 0;

    $("stat-high").textContent =
        summary.high_count ?? 0;

    $("stat-medium").textContent =
        summary.medium_count ?? 0;

    $("stat-low").textContent =
        summary.low_count ?? 0;

    $("stat-info").textContent =
        summary.info_count ?? 0;
}


async function loadDashboard() {
    try {
        await Promise.all([
            loadAccounts(),
            loadScans(),
        ]);

        if (state.scans.length) {
            const latest = state.scans[0];

            const summary = await apiFetch(
                `/scans/${latest.id}/summary`
            );

            updateDashboardStats(summary);

            $("latest-scan-description").textContent =
                `Scan #${latest.id} · ${latest.provider.toUpperCase()}`;

            $("latest-scan").innerHTML = `
                <div class="latest-grid">
                    <div>
                        <span>Status</span>
                        ${statusBadge(summary.status)}
                    </div>

                    <div>
                        <span>Total Findings</span>
                        <strong>${summary.total_findings}</strong>
                    </div>

                    <div>
                        <span>Execution Errors</span>
                        <strong>${summary.execution_error_count}</strong>
                    </div>

                    <div>
                        <span>Completed</span>
                        <strong>
                            ${formatDate(latest.completed_at)}
                        </strong>
                    </div>
                </div>

                <div class="button-group">
                    <button
                        class="primary-btn small"
                        onclick="openScan(${latest.id})"
                    >
                        Open Findings
                    </button>

                    <button
                        class="secondary-btn"
                        onclick="openReport(${latest.id})"
                    >
                        HTML Report
                    </button>
                </div>
            `;
        } else {
            updateDashboardStats({
                total_findings: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
            });

            $("latest-scan").innerHTML = `
                <div class="empty-state">
                    Run your first AWS scan to populate the dashboard.
                </div>
            `;
        }
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function startScan() {
    try {
        await loadAccounts();

        const activeAwsAccounts = state.accounts.filter(
            (account) =>
                account.provider === "aws" &&
                account.status === "active"
        );

        let cloudAccountId = null;

        if (activeAwsAccounts.length === 1) {
            cloudAccountId = activeAwsAccounts[0].id;
        } else if (activeAwsAccounts.length > 1) {
            const selected = prompt(
                "Enter the AWS account ID to scan:\n\n" +
                activeAwsAccounts
                    .map(
                        (account) =>
                            `${account.id}: ${account.name}`
                    )
                    .join("\n")
            );

            if (selected === null) {
                return;
            }

            cloudAccountId = Number(selected);

            if (
                !activeAwsAccounts.some(
                    (account) =>
                        account.id === cloudAccountId
                )
            ) {
                throw new Error(
                    "Invalid AWS cloud account selection."
                );
            }
        } else {
            throw new Error(
                "Add an active AWS account before starting a scan."
            );
        }

        const scan = await apiFetch("/scans", {
            method: "POST",
            body: JSON.stringify({
                provider: "aws",
                cloud_account_id: cloudAccountId,
            }),
        });

        state.currentScanId = scan.id;

        showToast(
            `Scan #${scan.id} queued successfully.`,
            "success"
        );

        await loadScans();

        await openScan(scan.id);

        startPolling(scan.id);
    } catch (error) {
        showToast(error.message, "error");
    }
}


function startPolling(scanId) {
    clearInterval(state.pollTimer);

    state.pollTimer = setInterval(
        async () => {
            try {
                const scan = await apiFetch(
                    `/scans/${scanId}`
                );

                if (
                    scan.status === "completed" ||
                    scan.status === "failed"
                ) {
                    clearInterval(state.pollTimer);

                    await loadScans();

                    if (state.currentScanId === scanId) {
                        await loadFindings(scanId);
                    }

                    showToast(
                        scan.status === "completed"
                            ? `Scan #${scanId} completed.`
                            : `Scan #${scanId} failed.`,
                        scan.status === "completed"
                            ? "success"
                            : "error"
                    );
                }
            } catch {
                clearInterval(state.pollTimer);
            }
        },
        3000
    );
}


async function openScan(scanId) {
    state.currentScanId = scanId;

    setView("findings");

    $("findings-scan-id").textContent = scanId;

    await loadFindings(scanId);
}


async function loadFindings(scanId) {
    try {
        const severity =
            $("severity-filter").value;

        const risk =
            $("risk-filter").value;

        const params = new URLSearchParams({
            limit: "100",
            offset: "0",
        });

        if (severity) {
            params.set("severity", severity);
        }

        if (risk) {
            params.set("risk_level", risk);
        }

        const result = await apiFetch(
            `/findings/scan/${scanId}?${params.toString()}`
        );

        const findings = result.items || [];

        $("findings-summary").textContent =
            `${result.total} finding(s) returned.`;

        const body = $("findings-body");

        if (!findings.length) {
            body.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        No findings match the current filters.
                    </td>
                </tr>
            `;
            return;
        }

        body.innerHTML = findings
            .map((finding) => `
                <tr>
                    <td>
                        <strong>
                            ${escapeHtml(finding.rule_id)}
                        </strong>
                    </td>

                    <td>
                        ${escapeHtml(finding.title)}
                    </td>

                    <td>
                        <span class="
                            severity
                            ${escapeHtml(
                                String(
                                    finding.severity
                                ).toLowerCase()
                            )}
                        ">
                            ${escapeHtml(finding.severity)}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(finding.risk_level)}
                        <small>
                            (${escapeHtml(finding.risk_score)})
                        </small>
                    </td>

                    <td>
                        <div>
                            ${escapeHtml(
                                finding.resource_type
                            )}
                        </div>
                        <code>
                            ${escapeHtml(
                                finding.resource_id
                            )}
                        </code>
                    </td>

                    <td>
                        ${escapeHtml(finding.provider)}
                    </td>

                    <td>
                        <button
                            class="secondary-btn tiny"
                            onclick="openFinding(${finding.id})"
                        >
                            Details
                        </button>
                    </td>
                </tr>
            `)
            .join("");
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function openFinding(findingId) {
    try {
        const finding = await apiFetch(
            `/findings/${findingId}`
        );

        $("finding-detail-title").textContent =
            finding.title;

        $("finding-detail-rule").textContent =
            `${finding.rule_id} · ${finding.resource_type}`;

        $("finding-detail-content").innerHTML = `
            <div class="detail-grid">

                <div class="detail-card">
                    <span>Severity</span>
                    <strong>
                        ${escapeHtml(finding.severity)}
                    </strong>
                </div>

                <div class="detail-card">
                    <span>Risk Level</span>
                    <strong>
                        ${escapeHtml(finding.risk_level)}
                    </strong>
                </div>

                <div class="detail-card">
                    <span>Risk Score</span>
                    <strong>
                        ${escapeHtml(finding.risk_score)}
                    </strong>
                </div>

                <div class="detail-card">
                    <span>Provider</span>
                    <strong>
                        ${escapeHtml(finding.provider)}
                    </strong>
                </div>
            </div>

            <div class="detail-section">
                <h4>Resource</h4>
                <code>
                    ${escapeHtml(finding.resource_id)}
                </code>
            </div>

            <div class="detail-section">
                <h4>Description</h4>
                <p>
                    ${escapeHtml(finding.description)}
                </p>
            </div>

            <div class="detail-section">
                <h4>Evidence</h4>
                <pre>${escapeHtml(
                    JSON.stringify(
                        finding.evidence || {},
                        null,
                        2
                    )
                )}</pre>
            </div>

            <div class="detail-section">
                <h4>Remediation</h4>
                <p>
                    ${escapeHtml(
                        finding.remediation || "No remediation provided."
                    )}
                </p>
            </div>

            <div class="detail-section">
                <h4>Compliance</h4>
                <div class="tag-list">
                    ${(finding.compliance || [])
                        .map(
                            (item) =>
                                `<span class="tag">
                                    ${escapeHtml(item)}
                                </span>`
                        )
                        .join("")}
                </div>
            </div>
        `;

        setView("finding-detail");
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function openLifecycle() {
    if (!state.currentScanId) {
        return;
    }

    try {
        const lifecycle = await apiFetch(
            `/findings/scan/${state.currentScanId}/lifecycle`
        );

        $("life-new").textContent = lifecycle.new;
        $("life-open").textContent = lifecycle.open;
        $("life-reopened").textContent =
            lifecycle.reopened;
        $("life-resolved").textContent =
            lifecycle.resolved;

        const body = $("lifecycle-body");

        if (!lifecycle.items.length) {
            body.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        No lifecycle records available.
                    </td>
                </tr>
            `;
        } else {
            body.innerHTML = lifecycle.items
                .map((item) => `
                    <tr>
                        <td>
                            <span class="
                                status
                                ${escapeHtml(
                                    item.status
                                )}
                            ">
                                ${escapeHtml(item.status)}
                            </span>
                        </td>
                        <td>${escapeHtml(item.rule_id)}</td>
                        <td>
                            ${escapeHtml(
                                item.resource_type
                            )}
                        </td>
                        <td class="mono">
                            ${escapeHtml(
                                item.resource_id
                            )}
                        </td>
                        <td>${item.first_seen_scan_id}</td>
                        <td>${item.last_seen_scan_id}</td>
                    </tr>
                `)
                .join("");
        }

        setView("lifecycle");
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function openReport(scanId = state.currentScanId) {
    if (!scanId) {
        return;
    }

    if (!state.token) {
        showToast("Your session has expired.", "error");
        showAuth();
        return;
    }

    /*
     * Open the tab synchronously from the user gesture so browsers do not
     * treat the authenticated report as an unwanted popup.
     *
     * The access token is sent only in the Authorization header. It is
     * never placed in the report URL, query string, fragment, filename,
     * or window location.
     */
    const reportWindow = window.open(
        "about:blank",
        "_blank",
        "noopener,noreferrer"
    );

    if (!reportWindow) {
        showToast(
            "The report window was blocked. Please allow popups for CloudSentinel.",
            "error"
        );
        return;
    }

    try {
        const response = await fetch(
            `${API}/reports/scans/${encodeURIComponent(scanId)}/html`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${state.token}`,
                    Accept: "text/html",
                },
                cache: "no-store",
                credentials: "same-origin",
            }
        );

        if (response.status === 401) {
            reportWindow.close();
            logout(false);
            throw new Error("Your session has expired.");
        }

        if (!response.ok) {
            reportWindow.close();

            let message =
                `Report request failed (${response.status})`;

            const contentType =
                response.headers.get("content-type") || "";

            if (contentType.includes("application/json")) {
                const payload = await response.json();
                message = payload.detail || message;
            }

            throw new Error(message);
        }

        const contentType =
            response.headers.get("content-type") || "";

        if (!contentType.toLowerCase().includes("text/html")) {
            reportWindow.close();
            throw new Error("The report response was not valid HTML.");
        }

        const reportBlob = await response.blob();
        const reportUrl = URL.createObjectURL(reportBlob);

        /*
         * The Blob URL contains no authentication material.
         * The object URL is revoked after the new tab has loaded it.
         */
        reportWindow.location.href = reportUrl;

        setTimeout(() => {
            URL.revokeObjectURL(reportUrl);
        }, 60_000);
    } catch (error) {
        if (!reportWindow.closed) {
            reportWindow.close();
        }

        showToast(error.message, "error");
    }
}



async function downloadPdfReport(scanId = state.currentScanId) {
    if (!scanId) {
        return;
    }

    if (!state.token) {
        showToast("Your session has expired.", "error");
        showAuth();
        return;
    }

    try {
        const response = await fetch(
            `${API}/reports/scans/${encodeURIComponent(scanId)}/pdf`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${state.token}`,
                    Accept: "application/pdf",
                },
                cache: "no-store",
                credentials: "same-origin",
            }
        );

        if (response.status === 401) {
            logout(false);
            throw new Error("Your session has expired.");
        }

        if (!response.ok) {
            let message =
                `PDF report request failed (${response.status})`;

            const contentType =
                response.headers.get("content-type") || "";

            if (contentType.includes("application/json")) {
                const payload = await response.json();
                message = payload.detail || message;
            }

            throw new Error(message);
        }

        const contentType =
            response.headers.get("content-type") || "";

        if (!contentType.toLowerCase().includes("application/pdf")) {
            throw new Error(
                "The report response was not a valid PDF."
            );
        }

        const blob = await response.blob();

        if (blob.size === 0) {
            throw new Error("The generated PDF was empty.");
        }

        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");

        anchor.href = url;
        anchor.download =
            `cloudsentinel-scan-${encodeURIComponent(scanId)}.pdf`;

        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 60_000);
    } catch (error) {
        showToast(error.message, "error");
    }
}


async function refreshCurrentView() {
    if (state.currentView === "dashboard") {
        await loadDashboard();
    } else if (state.currentView === "accounts") {
        await loadAccounts();
    } else if (state.currentView === "scans") {
        await loadScans();
    } else if (state.currentView === "findings") {
        await loadFindings(state.currentScanId);
    }
}


document.addEventListener(
    "DOMContentLoaded",
    async () => {
        document
            .querySelectorAll(".auth-tab")
            .forEach((tab) => {
                tab.addEventListener(
                    "click",
                    () => {
                        document
                            .querySelectorAll(".auth-tab")
                            .forEach((item) =>
                                item.classList.remove(
                                    "active"
                                )
                            );

                        tab.classList.add("active");

                        const isLogin =
                            tab.dataset.authTab ===
                            "login";

                        $("login-form")
                            .classList.toggle(
                                "hidden",
                                !isLogin
                            );

                        $("register-form")
                            .classList.toggle(
                                "hidden",
                                isLogin
                            );

                        clearAuthError();
                    }
                );
            });


        $("login-form").addEventListener(
            "submit",
            async (event) => {
                event.preventDefault();

                try {
                    await login(
                        $("login-email").value.trim(),
                        $("login-password").value,
                        $("login-tenant").value.trim()
                    );
                } catch (error) {
                    showAuthError(error.message);
                }
            }
        );


        $("register-form").addEventListener(
            "submit",
            async (event) => {
                event.preventDefault();

                try {
                    await register(
                        $("register-name").value.trim(),
                        $("register-tenant").value.trim(),
                        $("register-email").value.trim(),
                        $("register-password").value
                    );
                } catch (error) {
                    showAuthError(error.message);
                }
            }
        );


        document
            .querySelectorAll(".nav-item")
            .forEach((button) => {
                button.addEventListener(
                    "click",
                    async () => {
                        const view =
                            button.dataset.view;

                        setView(view);

                        try {
                            if (view === "dashboard") {
                                await loadDashboard();
                            } else if (
                                view === "accounts"
                            ) {
                                await loadAccounts();
                            } else if (
                                view === "scans"
                            ) {
                                await loadScans();
                            }
                        } catch (error) {
                            showToast(
                                error.message,
                                "error"
                            );
                        }
                    }
                );
            });


        $("logout-btn").addEventListener(
            "click",
            () => logout(true)
        );


        $("refresh-btn").addEventListener(
            "click",
            refreshCurrentView
        );


        $("dashboard-scan-btn").addEventListener(
            "click",
            startScan
        );


        $("history-scan-btn").addEventListener(
            "click",
            startScan
        );


        $("show-account-form-btn").addEventListener(
            "click",
            () => {
                $("account-form-container")
                    .classList.remove("hidden");
            }
        );


        $("cancel-account-btn").addEventListener(
            "click",
            () => {
                $("account-form-container")
                    .classList.add("hidden");
            }
        );


        $("account-form").addEventListener(
            "submit",
            createAccount
        );


        $("apply-filter-btn").addEventListener(
            "click",
            () => {
                if (state.currentScanId) {
                    loadFindings(
                        state.currentScanId
                    );
                }
            }
        );


        $("lifecycle-btn").addEventListener(
            "click",
            openLifecycle
        );


        $("report-btn").addEventListener(
            "click",
            () => openReport()
        );

        $("pdf-report-btn").addEventListener(
            "click",
            () => downloadPdfReport()
        );


        $("back-findings-btn").addEventListener(
            "click",
            () => setView("findings")
        );


        $("back-lifecycle-btn").addEventListener(
            "click",
            () => setView("findings")
        );


        if (state.token) {
            await loadCurrentUser();
        } else {
            showAuth();
        }
    }
);


window.openScan = openScan;
window.openFinding = openFinding;
window.openReport = openReport;
window.downloadPdfReport = downloadPdfReport;
