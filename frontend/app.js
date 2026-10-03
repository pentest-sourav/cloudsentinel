const API = "/api/v1";

const state = {
    token: localStorage.getItem("cloudsentinel_token"),
    user: null,

    scans: [],
    accounts: [],
    accountSetupId: null,

    currentScanId: null,
    currentScan: null,
    currentSummary: null,

    findings: [],
    filteredFindings: [],

    currentFinding: null,
    currentView: "dashboard",

    lifecycle: null,

    pollTimer: null,
    loading: false,
    reportScanId: null,
};


/* ============================================================
   HELPERS
============================================================ */

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

function safeNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function formatRelativeDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    const seconds = Math.floor(
        (Date.now() - date.getTime()) / 1000
    );

    if (seconds < 60) {
        return "just now";
    }

    const minutes = Math.floor(seconds / 60);

    if (minutes < 60) {
        return `${minutes}m ago`;
    }

    const hours = Math.floor(minutes / 60);

    if (hours < 24) {
        return `${hours}h ago`;
    }

    const days = Math.floor(hours / 24);

    if (days < 30) {
        return `${days}d ago`;
    }

    return date.toLocaleDateString();
}

function initials(value) {
    if (!value) {
        return "CS";
    }

    return String(value)
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((part) => part[0].toUpperCase())
        .join("");
}

function normalizeStatus(value) {
    return String(value || "unknown").toLowerCase();
}

function normalizeSeverity(value) {
    return String(value || "info").toLowerCase();
}

function severityBadge(severity) {
    const normalized = normalizeSeverity(severity);

    return `
        <span class="severity-badge ${escapeHtml(normalized)}">
            <span>●</span>
            ${escapeHtml(normalized)}
        </span>
    `;
}

function statusBadge(status) {
    const normalized = normalizeStatus(status);

    return `
        <span class="status ${escapeHtml(normalized)}">
            ${escapeHtml(status || "unknown")}
        </span>
    `;
}

function showToast(message, type = "info") {
    const container = $("toast-container");

    if (!container) {
        return;
    }

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    window.setTimeout(() => {
        toast.remove();
    }, 4500);
}

function setLoading(value) {
    state.loading = value;

    const bar = $("global-loading");

    if (bar) {
        bar.classList.toggle("hidden", !value);
    }

    document.body.classList.toggle("is-loading", value);
}

function setToken(token) {
    state.token = token;

    if (token) {
        localStorage.setItem("cloudsentinel_token", token);
    } else {
        localStorage.removeItem("cloudsentinel_token");
    }
}


/* ============================================================
   THEME
============================================================ */

function applyTheme(theme) {
    const normalized =
        theme === "light"
            ? "light"
            : "dark";

    document.documentElement.dataset.theme =
        normalized;

    localStorage.setItem(
        "cloudsentinel_theme",
        normalized
    );

    const button = $("theme-toggle");

    if (!button) {
        return;
    }

    const icon =
        button.querySelector(
            ".theme-toggle-icon"
        );

    const label =
        button.querySelector(
            ".theme-toggle-label"
        );

    const isLight =
        normalized === "light";

    if (icon) {
        icon.textContent =
            isLight ? "☾" : "☀";
    }

    if (label) {
        label.textContent =
            isLight ? "Dark" : "Light";
    }

    button.setAttribute(
        "aria-label",
        isLight
            ? "Switch to dark mode"
            : "Switch to light mode"
    );

    button.setAttribute(
        "title",
        isLight
            ? "Switch to dark mode"
            : "Switch to light mode"
    );
}

function toggleTheme() {
    const current =
        document.documentElement.dataset.theme ||
        "dark";

    applyTheme(
        current === "dark"
            ? "light"
            : "dark"
    );
}

function initializeTheme() {
    const saved =
        localStorage.getItem(
            "cloudsentinel_theme"
        );

    applyTheme(
        saved === "light"
            ? "light"
            : "dark"
    );
}

initializeTheme();

document.addEventListener("click", (event) => {
    const copyButton =
        event.target.closest("[data-copy-target]");

    if (copyButton) {
        const target =
            $(copyButton.dataset.copyTarget);

        if (target) {
            copyText(
                target.textContent.trim()
            );
        }

        return;
    }

    if (
        event.target.closest("#copy-trust-policy")
    ) {
        copyText(
            $("setup-trust-policy")
                .textContent
        );
    }
});




/* ============================================================
   API
============================================================ */

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

    let response;

    try {
        response = await fetch(`${API}${path}`, {
            ...options,
            headers,
        });
    } catch (error) {
        throw new Error(
            "Unable to reach CloudSentinel API. Check that the backend is running."
        );
    }

    if (response.status === 401) {
        logout(false);
        throw new Error(
            "Your session has expired. Please sign in again."
        );
    }

    // Some successful endpoints intentionally return 204 No Content.
    // Only callers that explicitly opt in use this path, so normal
    // JSON API behavior (including login/register) remains unchanged.
    if (
        options.expectEmptyResponse === true &&
        (response.status === 204 || response.status === 205)
    ) {
        return null;
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
        let message =
            `Request failed (${response.status})`;

        if (
            payload &&
            typeof payload === "object"
        ) {
            message =
                payload.detail ||
                payload.message ||
                message;
        } else if (payload) {
            message = String(payload);
        }

        throw new Error(message);
    }

    return payload;
}


/* ============================================================
   AUTH
============================================================ */

function showAuth() {
    $("auth-screen").classList.remove("hidden");
    $("app-screen").classList.add("hidden");
}

function showApp() {
    $("auth-screen").classList.add("hidden");
    $("app-screen").classList.remove("hidden");

    if (state.user) {
        const name =
            state.user.full_name ||
            state.user.email ||
            "CloudSentinel User";

        $("current-user-name").textContent = name;

        $("current-user-email").textContent =
            state.user.email ||
            "Authenticated";

        $("user-avatar").textContent =
            initials(name);

        if (state.user.tenant_name) {
            $("workspace-name").textContent =
                state.user.tenant_name;
        }
    }
}

function showAuthError(message) {
    const box = $("auth-error");

    box.textContent = message;
    box.classList.remove("hidden");
}

function clearAuthError() {
    $("auth-error").classList.add("hidden");
}

async function login(
    email,
    password,
    tenantName = ""
) {
    clearAuthError();

    try {
        const result =
            await apiFetch(
                "/auth/login",
                {
                    method: "POST",

                    body: JSON.stringify({
                        email,
                        password,
                        tenant_name:
                            tenantName ||
                            undefined,
                    }),
                }
            );

        setToken(
            result.access_token
        );

        state.user = {
            email,
        };

        showApp();

        await bootstrapApp();

    } catch (error) {
        showAuthError(
            error.message
        );
    }
}

async function register(
    fullName,
    tenantName,
    email,
    password
) {
    clearAuthError();

    try {
        await apiFetch(
            "/auth/register",
            {
                method: "POST",

                body: JSON.stringify({
                    full_name:
                        fullName,

                    tenant_name:
                        tenantName,

                    email,
                    password,
                }),
            }
        );

        await login(
            email,
            password,
            tenantName
        );

    } catch (error) {
        showAuthError(
            error.message
        );
    }
}

function logout(
    showMessage = true
) {
    if (state.pollTimer) {
        clearInterval(
            state.pollTimer
        );

        state.pollTimer = null;
    }

    setToken(null);

    state.user = null;
    state.scans = [];
    state.accounts = [];
    state.findings = [];
    state.currentScanId = null;
    state.currentScan = null;
    state.currentSummary = null;

    closeSidebar();

    showAuth();

    if (showMessage) {
        showToast(
            "Signed out successfully.",
            "info"
        );
    }
}


/* ============================================================
   NAVIGATION
============================================================ */

const VIEW_META = {
    dashboard: [
        "Security Overview",
        "Monitor your cloud security posture and risk.",
        "Overview",
    ],

    findings: [
        "Security Findings",
        "Investigate detected cloud security issues.",
        "Findings",
    ],

    scans: [
        "Scan History",
        "Review previous security assessments.",
        "Scan History",
    ],

    lifecycle: [
        "Finding Lifecycle",
        "Track changes across security scans.",
        "Changes",
    ],

    accounts: [
        "AWS Accounts",
        "Manage cloud accounts used for assessments.",
        "Cloud Accounts",
    ],

    reports: [
        "Security Reports",
        "Generate and review assessment reports.",
        "Reports",
    ],

    "finding-detail": [
        "Finding Detail",
        "Evidence, remediation and compliance context.",
        "Finding Detail",
    ],
};

function setView(view) {
    state.currentView = view;

    document
        .querySelectorAll(".view")
        .forEach((element) => {
            element.classList.add(
                "hidden"
            );
        });

    const target =
        $(`view-${view}`);

    if (target) {
        target.classList.remove(
            "hidden"
        );
    }

    document
        .querySelectorAll(".nav-item")
        .forEach((button) => {
            button.classList.toggle(
                "active",
                button.dataset.view === view
            );
        });

    const meta =
        VIEW_META[view] ||
        VIEW_META.dashboard;

    $("page-title").textContent =
        meta[0];

    $("page-subtitle").textContent =
        meta[1];

    $("breadcrumb-current").textContent =
        meta[2];

    closeSidebar();

    if (view === "accounts") {
        loadAccounts()
            .catch(handleError);
    }

    if (view === "scans") {
        renderHistory();
    }

    if (
        view === "findings" &&
        state.currentScanId
    ) {
        loadFindings(
            state.currentScanId
        ).catch(handleError);
    }

    if (
        view === "lifecycle" &&
        state.currentScanId
    ) {
        loadLifecycle(
            state.currentScanId
        ).catch(handleError);
    }

    if (view === "reports") {
        updateReportsView();
    }
}


/* ============================================================
   MOBILE NAV
============================================================ */

function openSidebar() {
    $("sidebar")
        .classList
        .add("mobile-open");

    $("sidebar-overlay")
        .classList
        .add("visible");
}

function closeSidebar() {
    $("sidebar")
        .classList
        .remove("mobile-open");

    $("sidebar-overlay")
        .classList
        .remove("visible");
}


/* ============================================================
   ACCOUNTS
============================================================ */

async function loadAccounts() {
    state.accounts =
        await apiFetch(
            "/cloud-accounts"
        );

    renderAccounts();
    populateScanAccounts();

    return state.accounts;
}


function renderAccounts() {
    const body =
        $("accounts-body");

    if (!state.accounts.length) {
        body.innerHTML = `
            <tr>
                <td colspan="7">
                    <div class="empty-state">
                        <div class="empty-icon">
                            ☁
                        </div>

                        <strong>
                            No AWS accounts configured
                        </strong>

                        <span>
                            Add an AWS account before starting a scan.
                        </span>
                    </div>
                </td>
            </tr>
        `;

        return;
    }

    body.innerHTML =
        state.accounts
            .map(
                (account) => `
            <tr>

                <td>
                    <strong>
                        ${escapeHtml(account.name)}
                    </strong>
                </td>

                <td>
                    ${escapeHtml(account.provider || "aws")}
                </td>

                <td class="mono">
                    ${escapeHtml(
                        account.external_account_id || "—"
                    )}
                </td>

                <td>
                    ${escapeHtml(account.region || "—")}
                </td>

                <td>
                    ${statusBadge(account.status)}
                </td>

                <td>
                    ${formatDate(account.created_at)}
                </td>

                <td>
                    <div class="account-actions">
                        <button
                            type="button"
                            class="secondary-btn tiny"
                            onclick="openAccountSetup(${account.id})"
                        >
                            Setup
                        </button>

                        <button
                            type="button"
                            class="secondary-btn tiny danger-action"
                            onclick="deleteAccount(${account.id}, '${escapeHtml(
                                account.name
                            ).replace(/'/g, "\\'")}')"
                        >
                            Delete
                        </button>
                    </div>
                </td>

            </tr>
        `
            )
            .join("");
}


async function deleteAccount(accountId, accountName) {
    const confirmed = window.confirm(
        `Delete AWS account "${accountName}"?\n\n` +
        "This permanently removes the account connection " +
        "and all scans and findings associated with it. " +
        "This action cannot be undone."
    );

    if (!confirmed) {
        return;
    }

    try {
        await apiFetch(
            `/cloud-accounts/${accountId}`,
            {
                method: "DELETE",
                expectEmptyResponse: true,
            }
        );

        if (state.accountSetupId === accountId) {
            closeAccountSetup();
        }

        await refreshDashboard();

        showToast(
            "AWS account and associated security history deleted.",
            "success"
        );
    } catch (error) {
        showToast(
            error.message,
            "error"
        );
    }
}


async function clearScanHistory() {
    if (!state.scans.length) {
        showToast(
            "There is no scan history to clear.",
            "info"
        );
        return;
    }

    const confirmed = window.confirm(
        "Clear scan history?\n\n" +
        "This permanently deletes all scans and findings " +
        "in this workspace. AWS cloud accounts will not be deleted. " +
        "This action cannot be undone."
    );

    if (!confirmed) {
        return;
    }

    try {
        setLoading(true);

        await apiFetch(
            "/scans/history",
            {
                method: "DELETE",
                expectEmptyResponse: true,
            }
        );

        state.scans = [];
        state.findings = [];
        state.filteredFindings = [];
        state.currentScanId = null;
        state.currentScan = null;
        state.currentSummary = null;
        state.lifecycle = null;
        state.reportScanId = null;

        renderRecentScans();
        renderHistory();

        renderLifecycle({
            items: [],
            counts: {
                new: 0,
                open: 0,
                reopened: 0,
                resolved: 0,
            },
        });

        resetDashboard();

        showToast(
            "Scan history and findings cleared successfully.",
            "success"
        );
    } catch (error) {
        handleError(error);
    } finally {
        setLoading(false);
    }
}


async function createAccount(event) {
    event.preventDefault();

    const button =
        event.submitter;

    if (button) {
        button.disabled = true;
    }

    try {
        const account =
            await apiFetch(
                "/cloud-accounts",
                {
                    method: "POST",

                    body: JSON.stringify({
                        name:
                            $("account-name")
                                .value
                                .trim(),

                        provider: "aws",

                        external_account_id:
                            $("account-id")
                                .value
                                .trim(),

                        role_arn:
                            $("role-arn")
                                .value
                                .trim(),

                        region:
                            $("account-region")
                                .value
                                .trim() ||
                            null,
                    }),
                }
            );

        $("account-form").reset();

        $("account-region")
            .value = "us-east-1";

        $("account-form-container")
            .classList
            .add("hidden");

        await loadAccounts();

        showToast(
            "AWS account added successfully.",
            "success"
        );

        await openAccountSetup(account.id);

    } catch (error) {
        showToast(
            error.message,
            "error"
        );

    } finally {
        if (button) {
            button.disabled = false;
        }
    }
}


async function openAccountSetup(accountId) {
    try {
        setLoading(true);

        const setup =
            await apiFetch(
                `/cloud-accounts/${accountId}/connection`
            );

        state.accountSetupId =
            accountId;

        $("setup-principal-arn")
            .textContent =
            setup.principal_arn ||
            "Configure CLOUDSENTINEL_AWS_PRINCIPAL_ARN";

        $("setup-external-id")
            .textContent =
            setup.external_id ||
            "—";

        const trustPolicy = {
            Version: "2012-10-17",
            Statement: [
                {
                    Effect: "Allow",
                    Principal: {
                        AWS:
                            setup.principal_arn ||
                            "CLOUDSENTINEL_AWS_PRINCIPAL_ARN",
                    },
                    Action: "sts:AssumeRole",
                    Condition: {
                        StringEquals: {
                            "sts:ExternalId":
                                setup.external_id,
                        },
                    },
                },
            ],
        };

        $("setup-trust-policy")
            .textContent =
            JSON.stringify(
                trustPolicy,
                null,
                2
            );

        $("account-connection-result")
            .textContent =
            "Not tested yet.";

        $("account-connection-result")
            .className =
            "connection-result neutral";

        $("account-setup-panel")
            .classList
            .remove("hidden");

        $("account-setup-panel")
            .scrollIntoView({
                behavior: "smooth",
                block: "start",
            });

    } catch (error) {
        handleError(error);
    } finally {
        setLoading(false);
    }
}


function closeAccountSetup() {
    state.accountSetupId = null;

    $("account-setup-panel")
        .classList
        .add("hidden");
}


async function testAccountConnection() {
    const accountId =
        state.accountSetupId;

    if (!accountId) {
        showToast(
            "Open an AWS account setup first.",
            "error"
        );
        return;
    }

    const button =
        $("test-account-connection");

    try {
        button.disabled = true;
        setLoading(true);

        const result =
            await apiFetch(
                `/cloud-accounts/${accountId}/test`,
                {
                    method: "POST",
                }
            );

        const resultElement =
            $("account-connection-result");

        if (result.connected) {
            resultElement.textContent =
                `Connected — AWS account ${result.actual_account_id} verified.`;

            resultElement.className =
                "connection-result success";

            showToast(
                "AWS connection verified successfully.",
                "success"
            );

            await loadAccounts();

        } else {
            resultElement.textContent =
                result.message ||
                "AWS connection failed.";

            resultElement.className =
                "connection-result error";

            showToast(
                result.message ||
                "AWS connection failed.",
                "error"
            );
        }

    } catch (error) {
        showToast(
            error.message,
            "error"
        );
    } finally {
        button.disabled = false;
        setLoading(false);
    }
}


async function copyText(value) {
    try {
        await navigator.clipboard.writeText(value);

        showToast(
            "Copied to clipboard.",
            "success"
        );
    } catch {
        showToast(
            "Unable to copy automatically.",
            "error"
        );
    }
}


window.deleteAccount =
    deleteAccount;

window.openAccountSetup =
    openAccountSetup;


/* ============================================================
   SCANS
============================================================ */

async function loadScans() {
    const result =
        await apiFetch(
            "/scans?limit=100&offset=0"
        );

    state.scans =
        result.items || [];

    renderRecentScans();
    renderHistory();

    return state.scans;
}

function getLatestScan() {
    if (!state.scans.length) {
        return null;
    }

    return state.scans[0];
}

async function openScan(scanId) {
    try {
        setLoading(true);

        const scan =
            await apiFetch(
                `/scans/${encodeURIComponent(
                    scanId
                )}`
            );

        state.currentScanId =
            scan.id;

        state.currentScan =
            scan;

        state.reportScanId =
            scan.id;

        await loadScanSummary(
            scan.id
        );

        setView(
            "findings"
        );

        await loadFindings(
            scan.id
        );

    } catch (error) {
        handleError(error);

    } finally {
        setLoading(false);
    }
}

async function loadScanSummary(
    scanId
) {
    const summary =
        await apiFetch(
            `/scans/${encodeURIComponent(
                scanId
            )}/summary`
        );

    state.currentSummary =
        summary;

    return summary;
}

function renderRecentScans() {
    const body =
        $("recent-scans-body");

    if (!state.scans.length) {
        body.innerHTML = `
            <tr>
                <td colspan="8">
                    <div class="empty-state">
                        <strong>
                            No scans yet
                        </strong>

                        <span>
                            Start an AWS scan to populate this table.
                        </span>
                    </div>
                </td>
            </tr>
        `;

        return;
    }

    body.innerHTML =
        state.scans
            .slice(0, 8)
            .map(
                (scan) => `
            <tr>

                <td>
                    <button
                        class="table-link"
                        type="button"
                        data-open-scan="${scan.id}"
                    >
                        #${escapeHtml(
                            scan.id
                        )}
                    </button>
                </td>

                <td>
                    ${escapeHtml(
                        scan.provider ||
                        "aws"
                    )}
                </td>

                <td>
                    ${statusBadge(
                        scan.status
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.total_findings
                    )}
                </td>

                <td>
                    <span class="risk-label critical">
                        ${safeNumber(
                            scan.critical_count
                        )}
                    </span>
                </td>

                <td>
                    <span class="risk-label high">
                        ${safeNumber(
                            scan.high_count
                        )}
                    </span>
                </td>

                <td>
                    ${formatDate(
                        scan.completed_at
                    )}
                </td>

                <td>
                    <button
                        class="secondary-btn"
                        type="button"
                        data-open-scan="${scan.id}"
                    >
                        View
                    </button>
                </td>

            </tr>
        `
            )
            .join("");
}

function renderHistory() {
    const body =
        $("history-body");

    $("history-total").textContent =
        state.scans.length;

    const latest =
        getLatestScan();

    $("history-latest-status")
        .textContent =
        latest?.status || "—";

    $("history-latest-findings")
        .textContent =
        latest
            ? safeNumber(
                  latest.total_findings
              )
            : "—";

    $("history-last-completed")
        .textContent =
        latest?.completed_at
            ? formatRelativeDate(
                  latest.completed_at
              )
            : "—";

    if (!state.scans.length) {
        body.innerHTML = `
            <tr>
                <td colspan="10">
                    <div class="empty-state">

                        <strong>
                            No scan history
                        </strong>

                        <span>
                            Run your first AWS security assessment.
                        </span>

                    </div>
                </td>
            </tr>
        `;

        return;
    }

    body.innerHTML =
        state.scans
            .map(
                (scan) => `
            <tr>

                <td>
                    <button
                        class="table-link"
                        type="button"
                        data-open-scan="${scan.id}"
                    >
                        #${escapeHtml(
                            scan.id
                        )}
                    </button>
                </td>

                <td>
                    ${escapeHtml(
                        scan.provider ||
                        "aws"
                    )}
                </td>

                <td>
                    ${statusBadge(
                        scan.status
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.total_findings
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.critical_count
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.high_count
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.medium_count
                    )}
                </td>

                <td>
                    ${safeNumber(
                        scan.low_count
                    )}
                </td>

                <td>
                    ${formatDate(
                        scan.completed_at
                    )}
                </td>

                <td>
                    <button
                        class="secondary-btn"
                        type="button"
                        data-open-scan="${scan.id}"
                    >
                        Review
                    </button>
                </td>

            </tr>
        `
            )
            .join("");
}

async function startScan(
    accountId
) {
    if (!accountId) {
        showToast(
            "Select an AWS account first.",
            "error"
        );

        return;
    }

    try {
        setLoading(true);

        const scan =
            await apiFetch(
                "/scans",
                {
                    method: "POST",

                    body: JSON.stringify({
                        provider: "aws",

                        cloud_account_id:
                            Number(
                                accountId
                            ),
                    }),
                }
            );

        state.currentScanId =
            scan.id;

        state.currentScan =
            scan;

        state.reportScanId =
            scan.id;

        closeScanModal();

        showToast(
            `AWS scan #${scan.id} started.`,
            "success"
        );

        await loadScans();

        setView(
            "dashboard"
        );

        await refreshDashboard();

        startScanPolling(
            scan.id
        );

    } catch (error) {
        handleError(error);

    } finally {
        setLoading(false);
    }
}

function startScanPolling(
    scanId
) {
    if (state.pollTimer) {
        clearInterval(
            state.pollTimer
        );
    }

    let attempts = 0;

    state.pollTimer =
        setInterval(
            async () => {
                attempts += 1;

                try {
                    const scan =
                        await apiFetch(
                            `/scans/${encodeURIComponent(
                                scanId
                            )}`
                        );

                    state.currentScan =
                        scan;

                    const index =
                        state.scans.findIndex(
                            (item) =>
                                item.id ===
                                scan.id
                        );

                    if (index >= 0) {
                        state.scans[
                            index
                        ] = {
                            ...state
                                .scans[
                                index
                            ],

                            ...scan,
                        };
                    } else {
                        state.scans.unshift(
                            scan
                        );
                    }

                    renderRecentScans();
                    renderHistory();

                    if (state.currentView === "dashboard") {
                        renderDashboardSummary(state.currentSummary, scan);
                    }

                    if (
                        [
                            "completed",
                            "failed",
                        ].includes(
                            normalizeStatus(
                                scan.status
                            )
                        )
                    ) {
                        clearInterval(
                            state.pollTimer
                        );

                        state.pollTimer =
                            null;

                        await refreshDashboard();

                        showToast(
                            scan.status ===
                                "completed"
                                ? `Scan #${scan.id} completed.`
                                : `Scan #${scan.id} failed.`,

                            scan.status ===
                                "completed"
                                ? "success"
                                : "error"
                        );
                    }

                    if (attempts >= 60) {
                        clearInterval(
                            state.pollTimer
                        );

                        state.pollTimer =
                            null;
                    }

                } catch {
                    if (attempts >= 10) {
                        clearInterval(
                            state.pollTimer
                        );

                        state.pollTimer =
                            null;
                    }
                }

            },
            5000
        );
}


/* ============================================================
   DASHBOARD
============================================================ */

async function refreshDashboard() {
    try {
        setLoading(true);

        await Promise.all([
            loadScans(),
            loadAccounts(),
        ]);

        const latest =
            getLatestScan();

        if (!latest) {
            resetDashboard();
            return;
        }

        state.currentScanId =
            latest.id;

        state.currentScan =
            latest;

        state.reportScanId =
            latest.id;

        await loadScanSummary(
            latest.id
        );

        renderDashboardSummary(
            state.currentSummary,
            latest
        );

        await loadFindings(
            latest.id,
            true
        );

        updateReportsView();

        $("last-refresh")
            .textContent =
            `Updated ${new Date().toLocaleTimeString()}`;

    } finally {
        setLoading(false);
    }
}

function renderDashboardSummary(
    summary,
    scan
) {
    const total =
        safeNumber(
            summary?.total_findings
        );

    const critical =
        safeNumber(
            summary?.critical_count
        );

    const high =
        safeNumber(
            summary?.high_count
        );

    const medium =
        safeNumber(
            summary?.medium_count
        );

    const low =
        safeNumber(
            summary?.low_count
        );

    const info =
        safeNumber(
            summary?.info_count
        );

    $("stat-total")
        .textContent = total;

    $("stat-critical")
        .textContent =
        critical;

    $("stat-high")
        .textContent =
        high;

    $("stat-medium")
        .textContent =
        medium;

    $("stat-low-info")
        .textContent =
        low + info;

    $("risk-total")
        .textContent = total;

    $("legend-critical")
        .textContent =
        critical;

    $("legend-high")
        .textContent =
        high;

    $("legend-medium")
        .textContent =
        medium;

    $("legend-low")
        .textContent =
        low;

    $("legend-info")
        .textContent =
        info;

    $("nav-findings-count")
        .textContent =
        critical + high;

    $("nav-findings-count")
        .classList.toggle(
            "hidden",
            critical + high === 0
        );

    renderRiskRing({
        critical,
        high,
        medium,
        low,
        info,
        total,
    });

    const status =
        normalizeStatus(
            scan?.status ||
            summary?.status
        );

    const statusElement =
        $("latest-scan-status");

    statusElement.textContent =
        scan?.status ||
        summary?.status ||
        "Unknown";

    statusElement.className =
        `status-pill ${escapeHtml(
            status
        )}`;

    $("latest-scan-description")
        .textContent =
        scan?.completed_at
            ? `Completed ${formatRelativeDate(
                  scan.completed_at
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

    const segments =
        values.map(
            ([count, color]) => {

                const degrees =
                    (count / total) *
                    360;

                const start =
                    cursor;

                cursor += degrees;

                return `${color} ${start}deg ${cursor}deg`;
            }
        );

    ring.style.background =
        `conic-gradient(${segments.join(
            ", "
        )})`;
}

function resetDashboard() {
    state.currentScanId = null;
    state.currentScan = null;
    state.currentSummary = null;
    state.findings = [];
    state.filteredFindings = [];
    state.lifecycle = null;
    state.reportScanId = null;

    $("findings-scan-label")
        .textContent = "No scan selected";

    renderFindings();

    $("stat-total")
        .textContent = "0";

    $("stat-critical")
        .textContent = "0";

    $("stat-high")
        .textContent = "0";

    $("stat-medium")
        .textContent = "0";

    $("stat-low-info")
        .textContent = "0";

    $("risk-total")
        .textContent = "0";

    $("legend-critical")
        .textContent = "0";

    $("legend-high")
        .textContent = "0";

    $("legend-medium")
        .textContent = "0";

    $("legend-low")
        .textContent = "0";

    $("legend-info")
        .textContent = "0";

    $("nav-findings-count")
        .classList
        .add("hidden");

    $("latest-scan-status")
        .textContent =
        "No scan";

    $("latest-scan-status")
        .className =
        "status-pill neutral";

    $("latest-scan-description")
        .textContent =
        "No completed scan yet.";

    $("latest-scan").innerHTML = `
        <div class="empty-state compact">

            <div class="empty-icon">
                ⌁
            </div>

            <strong>
                No security scan yet
            </strong>

            <span>
                Run an AWS scan to populate your security posture.
            </span>

        </div>
    `;

    $("risk-ring").style.background =
        "conic-gradient(#18283d 0deg 360deg)";

    updateReportsView();
}


/* ============================================================
   FINDINGS
============================================================ */

async function loadFindings(
    scanId,
    silent = false
) {
    if (!scanId) {
        return [];
    }

    try {
        if (!silent) {
            setLoading(true);
        }

        const result =
            await apiFetch(
                `/findings/scan/${encodeURIComponent(
                    scanId
                )}?limit=100&offset=0`
            );

        state.findings =
            result.items ||
            result.findings ||
            [];

        state.currentScanId =
            scanId;

        applyFindingFilters();

        $("findings-scan-label")
            .textContent =
            `Scan #${scanId}`;

        return state.findings;

    } finally {
        if (!silent) {
            setLoading(false);
        }
    }
}

function applyFindingFilters() {
    const query =
        $("finding-search")
            .value
            .trim()
            .toLowerCase();

    const severity =
        $("severity-filter")
            .value;

    const risk =
        $("risk-filter")
            .value;

    state.filteredFindings =
        state.findings.filter(
            (finding) => {

                const haystack = [
                    finding.rule_id,
                    finding.title,
                    finding.description,
                    finding.provider,
                    finding.resource_type,
                    finding.resource_id,
                ]
                    .filter(Boolean)
                    .join(" ")
                    .toLowerCase();

                if (
                    query &&
                    !haystack.includes(
                        query
                    )
                ) {
                    return false;
                }

                if (
                    severity &&
                    normalizeSeverity(
                        finding.severity
                    ) !== severity
                ) {
                    return false;
                }

                if (
                    risk &&
                    normalizeSeverity(
                        finding.risk_level
                    ) !== risk
                ) {
                    return false;
                }

                return true;
            }
        );

    renderFindings();
}

function renderFindings() {
    const body =
        $("findings-body");

    const items =
        state.filteredFindings;

    $("findings-count-label")
        .textContent =
        `${items.length} finding${
            items.length === 1
                ? ""
                : "s"
        }`;

    if (!items.length) {
        body.innerHTML = `
            <tr>
                <td colspan="7">

                    <div class="empty-state">

                        <div class="empty-icon">
                            ✓
                        </div>

                        <strong>
                            No matching findings
                        </strong>

                        <span>
                            Try changing your filters or run another scan.
                        </span>

                    </div>

                </td>
            </tr>
        `;

        return;
    }

    body.innerHTML =
        items
            .map(
                (finding) => {

                    const severity =
                        normalizeSeverity(
                            finding.severity
                        );

                    const risk =
                        normalizeSeverity(
                            finding.risk_level
                        );

                    return `
                <tr>

                    <td>
                        ${severityBadge(
                            severity
                        )}
                    </td>

                    <td>
                        <button
                            class="table-link finding-title"
                            type="button"
                            data-open-finding="${
                                finding.id
                            }"
                        >
                            ${escapeHtml(
                                finding.title ||
                                "Untitled finding"
                            )}
                        </button>
                    </td>

                    <td class="mono">
                        ${escapeHtml(
                            finding.rule_id ||
                            "—"
                        )}
                    </td>

                    <td
                        class="resource-cell"
                        title="${escapeHtml(
                            finding.resource_id
                        )}"
                    >
                        ${escapeHtml(
                            finding.resource_id ||
                            "—"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            finding.provider ||
                            "—"
                        )}
                    </td>

                    <td>
                        <span class="risk-label ${escapeHtml(
                            risk
                        )}">
                            ${escapeHtml(
                                finding.risk_level ||
                                "—"
                            )}
                        </span>
                    </td>

                    <td>
                        <button
                            class="secondary-btn"
                            type="button"
                            data-open-finding="${
                                finding.id
                            }"
                        >
                            View
                        </button>
                    </td>

                </tr>
            `;
                }
            )
            .join("");
}

async function openFinding(
    findingId
) {
    try {
        setLoading(true);

        const finding =
            await apiFetch(
                `/findings/${encodeURIComponent(
                    findingId
                )}`
            );

        state.currentFinding =
            finding;

        renderFindingDetail(
            finding
        );

        openFindingDrawer(
            finding
        );

    } catch (error) {
        handleError(error);

    } finally {
        setLoading(false);
    }
}

function renderFindingDetail(
    finding
) {
    const title =
        finding.title ||
        "Security finding";

    $("finding-detail-title")
        .textContent =
        title;

    $("finding-detail-rule")
        .textContent =
        finding.rule_id
            ? `Rule ${finding.rule_id}`
            : "Cloud security finding";

    const compliance =
        finding.compliance;

    let complianceHtml =
        "—";

    if (Array.isArray(
        compliance
    )) {
        complianceHtml =
            compliance
                .map(
                    (item) =>
                        escapeHtml(
                            typeof item ===
                                "string"
                                ? item
                                : JSON.stringify(
                                      item
                                  )
                        )
                )
                .join(", ");

    } else if (
        compliance &&
        typeof compliance ===
            "object"
    ) {
        complianceHtml =
            escapeHtml(
                JSON.stringify(
                    compliance,
                    null,
                    2
                )
            );

    } else if (compliance) {
        complianceHtml =
            escapeHtml(
                compliance
            );
    }

    $("finding-detail-content")
        .innerHTML = `
        <div class="detail-grid">

            <div class="detail-card">

                <h3>
                    Description
                </h3>

                <p>
                    ${escapeHtml(
                        finding.description ||
                        "No description available."
                    )}
                </p>


                <div class="detail-field">

                    <span>
                        Evidence
                    </span>

                    <div class="evidence-box">
                        ${escapeHtml(
                            formatObject(
                                finding.evidence
                            )
                        )}
                    </div>

                </div>


                <div class="detail-field">

                    <span>
                        Remediation
                    </span>

                    <div class="remediation-box">
                        ${escapeHtml(
                            formatObject(
                                finding.remediation
                            )
                        )}
                    </div>

                </div>


                <div class="detail-field">

                    <span>
                        Compliance
                    </span>

                    <div class="remediation-box">
                        ${complianceHtml}
                    </div>

                </div>

            </div>


            <div class="detail-card">

                <h3>
                    Risk context
                </h3>

                <div class="detail-field">

                    <span>
                        Severity
                    </span>

                    ${severityBadge(
                        finding.severity
                    )}

                </div>

                <div class="detail-field">

                    <span>
                        Risk level
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.risk_level ||
                            "—"
                        )}
                    </strong>

                </div>

                <div class="detail-field">

                    <span>
                        Risk score
                    </span>

                    <strong>
                        ${
                            finding.risk_score ??
                            "—"
                        }
                    </strong>

                </div>

                <div class="detail-field">

                    <span>
                        Provider
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.provider ||
                            "—"
                        )}
                    </strong>

                </div>

                <div class="detail-field">

                    <span>
                        Resource type
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.resource_type ||
                            "—"
                        )}
                    </strong>

                </div>

                <div class="detail-field">

                    <span>
                        Resource ID
                    </span>

                    <code>
                        ${escapeHtml(
                            finding.resource_id ||
                            "—"
                        )}
                    </code>

                </div>

                <div class="detail-field">

                    <span>
                        Scan
                    </span>

                    <strong>
                        #${escapeHtml(
                            finding.scan_id ??
                            state.currentScanId ??
                            "—"
                        )}
                    </strong>

                </div>

            </div>

        </div>
    `;

    $("drawer-title")
        .textContent =
        title;

    $("drawer-content")
        .innerHTML = `
            <div class="drawer-meta">

                <div>
                    <span>
                        Severity
                    </span>

                    ${severityBadge(
                        finding.severity
                    )}
                </div>

                <div>
                    <span>
                        Risk
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.risk_level ||
                            "—"
                        )}
                    </strong>
                </div>

                <div>
                    <span>
                        Rule
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.rule_id ||
                            "—"
                        )}
                    </strong>
                </div>

                <div>
                    <span>
                        Provider
                    </span>

                    <strong>
                        ${escapeHtml(
                            finding.provider ||
                            "—"
                        )}
                    </strong>
                </div>

            </div>


            <div class="drawer-section">

                <h3>
                    What was detected
                </h3>

                <p>
                    ${escapeHtml(
                        finding.description ||
                        "No description available."
                    )}
                </p>

            </div>


            <div class="drawer-section">

                <h3>
                    Affected resource
                </h3>

                <div class="evidence-box">
                    ${escapeHtml(
                        finding.resource_id ||
                        "Unknown resource"
                    )}
                </div>

            </div>


            <div class="drawer-section">

                <h3>
                    Evidence
                </h3>

                <div class="evidence-box">
                    ${escapeHtml(
                        formatObject(
                            finding.evidence
                        )
                    )}
                </div>

            </div>


            <div class="drawer-section">

                <h3>
                    Remediation
                </h3>

                <div class="remediation-box">
                    ${escapeHtml(
                        formatObject(
                            finding.remediation
                        )
                    )}
                </div>

            </div>


            <div class="drawer-section">

                <h3>
                    Compliance
                </h3>

                <div class="remediation-box">
                    ${complianceHtml}
                </div>

            </div>
        `;
}

function formatObject(value) {
    if (
        value === null ||
        value === undefined
    ) {
        return "No data available.";
    }

    if (
        typeof value ===
        "string"
    ) {
        return value;
    }

    try {
        return JSON.stringify(
            value,
            null,
            2
        );
    } catch {
        return String(value);
    }
}


/* ============================================================
   LIFECYCLE
============================================================ */

async function loadLifecycle(
    scanId
) {
    if (!scanId) {
        return null;
    }

    try {
        setLoading(true);

        const result =
            await apiFetch(
                `/findings/scan/${encodeURIComponent(
                    scanId
                )}/lifecycle`
            );

        state.lifecycle =
            result;

        renderLifecycle(
            result
        );

        return result;

    } finally {
        setLoading(false);
    }
}

function renderLifecycle(
    result
) {
    const items =
        result?.items ||
        result?.findings ||
        result?.lifecycle ||
        [];

    const counts =
        result?.counts ||
        {};

    $("life-new")
        .textContent =
        safeNumber(
            counts.new ??
            result?.new_count
        );

    $("life-open")
        .textContent =
        safeNumber(
            counts.open ??
            result?.open_count
        );

    $("life-reopened")
        .textContent =
        safeNumber(
            counts.reopened ??
            result?.reopened_count
        );

    $("life-resolved")
        .textContent =
        safeNumber(
            counts.resolved ??
            result?.resolved_count
        );

    $("lifecycle-description")
        .textContent =
        state.currentScanId
            ? `Lifecycle comparison for scan #${state.currentScanId}.`
            : "No scan selected.";

    const body =
        $("lifecycle-body");

    if (
        !Array.isArray(items) ||
        !items.length
    ) {
        body.innerHTML = `
            <tr>

                <td colspan="6">

                    <div class="empty-state">

                        <strong>
                            No lifecycle changes
                        </strong>

                        <span>
                            There is no historical comparison
                            available for this scan.
                        </span>

                    </div>

                </td>

            </tr>
        `;

        return;
    }

    body.innerHTML =
        items
            .map(
                (item) => `
            <tr>

                <td>
                    ${statusBadge(
                        item.status ||
                        item.lifecycle_status ||
                        "unknown"
                    )}
                </td>

                <td class="mono">
                    ${escapeHtml(
                        item.rule_id ||
                        item.rule ||
                        "—"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        item.resource_type ||
                        "—"
                    )}
                </td>

                <td class="resource-cell">
                    ${escapeHtml(
                        item.resource_id ||
                        "—"
                    )}
                </td>

                <td>
                    ${formatDate(
                        item.first_seen_at ||
                        item.first_seen
                    )}
                </td>

                <td>
                    ${formatDate(
                        item.last_seen_at ||
                        item.last_seen
                    )}
                </td>

            </tr>
        `
            )
            .join("");
}


/* ============================================================
   REPORTS
============================================================ */

function updateReportsView() {
    const scan =
        state.currentScan ||
        getLatestScan();

    const scanId =
        state.reportScanId ||
        scan?.id;

    if (!scanId) {
        $("report-scan-title")
            .textContent =
            "No scan selected";

        $("report-scan-description")
            .textContent =
            "Run a scan to generate security reports.";

        return;
    }

    $("report-scan-title")
        .textContent =
        `Security assessment #${scanId}`;

    $("report-scan-description")
        .textContent =
        scan?.completed_at
            ? `Completed ${formatDate(
                  scan.completed_at
              )}.`
            : "Report is available for this scan.";
}

function getReportUrl(
    scanId,
    format
) {
    if (format === "html") {
        return (
            `${API}` +
            `/reports/scans/${encodeURIComponent(scanId)}/html`
        );
    }

    if (format === "pdf") {
        return (
            `${API}` +
            `/reports/scans/${encodeURIComponent(scanId)}/pdf`
        );
    }

    throw new Error(
        `Unsupported report format: ${format}`
    );
}

function openHtmlReport() {
    const scanId =
        state.reportScanId ||
        state.currentScanId ||
        getLatestScan()?.id;

    if (!scanId) {
        showToast(
            "Run a scan before opening a report.",
            "error"
        );

        return;
    }

    window.open(
        getReportUrl(
            scanId,
            "html"
        ),
        "_blank",
        "noopener,noreferrer"
    );
}

async function downloadPdfReport() {
    const scanId =
        state.reportScanId ||
        state.currentScanId ||
        getLatestScan()?.id;

    if (!scanId) {
        showToast(
            "Run a scan before downloading a report.",
            "error"
        );

        return;
    }

    try {
        setLoading(true);

        const response =
            await fetch(
                getReportUrl(
                    scanId,
                    "pdf"
                ),
                {
                    headers: state.token
                        ? {
                              Authorization: `Bearer ${state.token}`,
                          }
                        : {},
                }
            );

        if (
            response.status ===
            401
        ) {
            logout(false);

            throw new Error(
                "Your session has expired."
            );
        }

        if (!response.ok) {
            const text =
                await response.text();

            throw new Error(
                text ||
                `PDF request failed (${response.status})`
            );
        }

        const blob =
            await response.blob();

        const url =
            URL.createObjectURL(
                blob
            );

        const link =
            document.createElement(
                "a"
            );

        link.href = url;

        link.download =
            `cloudsentinel-scan-${scanId}.pdf`;

        document.body.appendChild(
            link
        );

        link.click();

        link.remove();

        URL.revokeObjectURL(
            url
        );

        showToast(
            "PDF report downloaded.",
            "success"
        );

    } catch (error) {
        handleError(error);

    } finally {
        setLoading(false);
    }
}


/* ============================================================
   SCAN MODAL
============================================================ */

function openScanModal() {
    populateScanAccounts();

    $("scan-modal")
        .classList
        .remove("hidden");
}

function closeScanModal() {
    $("scan-modal")
        .classList
        .add("hidden");
}

function populateScanAccounts() {
    const select =
        $("scan-account-select");

    if (!select) {
        return;
    }

    if (!state.accounts.length) {
        select.innerHTML = `
            <option value="">
                No AWS accounts configured
            </option>
        `;

        return;
    }

    select.innerHTML = `
        <option value="">
            Select an AWS account
        </option>

        ${state.accounts
            .map(
                (account) => `
                    <option
                        value="${escapeHtml(
                            account.id
                        )}"
                    >
                        ${escapeHtml(
                            account.name
                        )}
                        ${
                            account.external_account_id
                                ? ` — ${escapeHtml(
                                      account.external_account_id
                                  )}`
                                : ""
                        }
                    </option>
                `
            )
            .join("")}
    `;
}


/* ============================================================
   BOOTSTRAP
============================================================ */

async function loadCurrentUser() {
    try {
        const response =
            await apiFetch(
                "/auth/me"
            );

        state.user =
            response;

        showApp();

        await bootstrapApp();

    } catch {
        /*
         * Some deployments may not expose /auth/me.
         * The authenticated API calls remain authoritative.
         */

        if (state.token) {
            showApp();

            try {
                await bootstrapApp();
            } catch {
                showAuth();
            }
        } else {
            showAuth();
        }
    }
}

async function bootstrapApp() {
    showApp();

    setView(
        "dashboard"
    );

    try {
        await refreshDashboard();

    } catch (error) {
        handleError(error);

        resetDashboard();
    }
}


/* ============================================================
   ERROR HANDLING
============================================================ */

function handleError(error) {
    console.error(error);

    if (
        error &&
        error.message
    ) {
        showToast(
            error.message,
            "error"
        );
    } else {
        showToast(
            "Something went wrong.",
            "error"
        );
    }
}


/* ============================================================
   DRAWER
============================================================ */

function openFindingDrawer(
    finding
) {
    renderFindingDetail(
        finding
    );

    $("finding-drawer")
        .classList
        .remove("hidden");
}

function closeFindingDrawer() {
    $("finding-drawer")
        .classList
        .add("hidden");
}


/* ============================================================
   EVENT HANDLERS
============================================================ */

function bindEvents() {

    /* AUTH TABS */

    document
        .querySelectorAll(
            "[data-auth-tab]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const tab =
                            button.dataset
                                .authTab;

                        document
                            .querySelectorAll(
                                ".auth-tab"
                            )
                            .forEach(
                                (item) => {

                                    item.classList.toggle(
                                        "active",
                                        item ===
                                            button
                                    );
                                }
                            );

                        $("login-form")
                            .classList
                            .toggle(
                                "hidden",
                                tab !==
                                    "login"
                            );

                        $("register-form")
                            .classList
                            .toggle(
                                "hidden",
                                tab !==
                                    "register"
                            );

                        clearAuthError();
                    }
                );
            }
        );


    /* LOGIN */

    $("login-form")
        .addEventListener(
            "submit",
            async (event) => {

                event.preventDefault();

                await login(
                    $("login-email")
                        .value
                        .trim(),

                    $("login-password")
                        .value,

                    $("login-tenant")
                        .value
                        .trim()
                );
            }
        );


    /* REGISTER */

    $("register-form")
        .addEventListener(
            "submit",
            async (event) => {

                event.preventDefault();

                await register(
                    $("register-name")
                        .value
                        .trim(),

                    $("register-tenant")
                        .value
                        .trim(),

                    $("register-email")
                        .value
                        .trim(),

                    $("register-password")
                        .value
                );
            }
        );


    /* NAVIGATION */

    document
        .querySelectorAll(
            ".nav-item"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        setView(
                            button.dataset
                                .view
                        );
                    }
                );
            }
        );


    /* THEME */

    $("theme-toggle")
        .addEventListener(
            "click",
            toggleTheme
        );


    /* REFRESH */

    $("refresh-btn")
        .addEventListener(
            "click",
            async () => {

                try {
                    await refreshDashboard();

                    showToast(
                        "Dashboard refreshed.",
                        "success"
                    );

                } catch (error) {
                    handleError(error);
                }
            }
        );


    /* LOGOUT */

    $("logout-btn")
        .addEventListener(
            "click",
            () => logout(true)
        );


    /* MOBILE */

    $("mobile-sidebar-open")
        .addEventListener(
            "click",
            openSidebar
        );

    $("mobile-sidebar-close")
        .addEventListener(
            "click",
            closeSidebar
        );

    $("sidebar-overlay")
        .addEventListener(
            "click",
            closeSidebar
        );


    /* CLEAR SCAN HISTORY */

    $("clear-history-btn")
        .addEventListener(
            "click",
            async () => {
                await clearScanHistory();
            }
        );


    /* SCAN BUTTONS */

    [
        "header-scan-btn",
        "hero-scan-btn",
        "dashboard-scan-btn",
        "history-scan-btn",
    ]
        .map(
            (id) => $(id)
        )
        .filter(Boolean)
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    async () => {

                        try {

                            if (
                                !state.accounts
                                    .length
                            ) {
                                await loadAccounts();
                            }

                            openScanModal();

                        } catch (error) {
                            handleError(
                                error
                            );
                        }
                    }
                );
            }
        );


    /* SCAN MODAL */

    $("scan-modal-close")
        .addEventListener(
            "click",
            closeScanModal
        );

    $("scan-cancel-btn")
        .addEventListener(
            "click",
            closeScanModal
        );

    $("scan-form")
        .addEventListener(
            "submit",
            async (event) => {

                event.preventDefault();

                await startScan(
                    $("scan-account-select")
                        .value
                );
            }
        );


    /* ACCOUNT FORM */

    $("show-account-form-btn")
        .addEventListener(
            "click",
            () => {

                $("account-form-container")
                    .classList
                    .remove("hidden");

                setView(
                    "accounts"
                );

                window.scrollTo({
                    top: 0,
                    behavior: "smooth",
                });
            }
        );

    $("cancel-account-btn")
        .addEventListener(
            "click",
            () => {

                $("account-form-container")
                    .classList
                    .add("hidden");
            }
        );

    $("cancel-account-form-btn")
        .addEventListener(
            "click",
            () => {

                $("account-form-container")
                    .classList
                    .add("hidden");
            }
        );

    $("account-form")
        .addEventListener(
            "submit",
            createAccount
        );


    /* FINDING FILTERS */

    $("finding-search")
        .addEventListener(
            "input",
            applyFindingFilters
        );

    $("severity-filter")
        .addEventListener(
            "change",
            applyFindingFilters
        );

    $("risk-filter")
        .addEventListener(
            "change",
            applyFindingFilters
        );

    $("clear-filters-btn")
        .addEventListener(
            "click",
            () => {

                $("finding-search")
                    .value = "";

                $("severity-filter")
                    .value = "";

                $("risk-filter")
                    .value = "";

                applyFindingFilters();
            }
        );


    /* FINDINGS REFRESH */

    $("findings-refresh-btn")
        .addEventListener(
            "click",
            async () => {

                if (
                    !state.currentScanId
                ) {
                    showToast(
                        "No scan selected.",
                        "error"
                    );

                    return;
                }

                try {

                    await loadFindings(
                        state.currentScanId
                    );

                    showToast(
                        "Findings refreshed.",
                        "success"
                    );

                } catch (error) {
                    handleError(
                        error
                    );
                }
            }
        );


    /* FINDINGS REPORT */

    $("findings-report-btn")
        .addEventListener(
            "click",
            openHtmlReport
        );


    /* FINDINGS LIFECYCLE */

    $("findings-lifecycle-btn")
        .addEventListener(
            "click",
            async () => {

                if (
                    !state.currentScanId
                ) {
                    showToast(
                        "No scan selected.",
                        "error"
                    );

                    return;
                }

                try {

                    await loadLifecycle(
                        state.currentScanId
                    );

                    setView(
                        "lifecycle"
                    );

                } catch (error) {
                    handleError(
                        error
                    );
                }
            }
        );


    /* LIFECYCLE BACK */

    $("back-lifecycle-btn")
        .addEventListener(
            "click",
            () => {

                setView(
                    "findings"
                );
            }
        );


    /* FINDING DETAIL BACK */

    $("back-findings-btn")
        .addEventListener(
            "click",
            () => {

                setView(
                    "findings"
                );
            }
        );


    /* DRAWER */

    $("drawer-close")
        .addEventListener(
            "click",
            closeFindingDrawer
        );

    $("finding-drawer")
        .addEventListener(
            "click",
            (event) => {

                if (
                    event.target ===
                    $("finding-drawer")
                ) {
                    closeFindingDrawer();
                }
            }
        );


    /* REPORTS */

    $("report-html-btn")
        .addEventListener(
            "click",
            openHtmlReport
        );

    $("report-pdf-btn")
        .addEventListener(
            "click",
            downloadPdfReport
        );

    $("hero-report-btn")
        .addEventListener(
            "click",
            () => {

                setView(
                    "reports"
                );
            }
        );


    /* QUICK LINKS */

    document
        .querySelectorAll(
            "[data-view-link]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        setView(
                            button.dataset
                                .viewLink
                        );
                    }
                );
            }
        );


    /* KPI SEVERITY LINKS */

    document
        .querySelectorAll(
            "[data-severity-link]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        $("severity-filter")
                            .value =
                            button.dataset
                                .severityLink;

                        setView(
                            "findings"
                        );

                        applyFindingFilters();
                    }
                );
            }
        );


    $("distribution-findings-btn")
        .addEventListener(
            "click",
            () => {

                setView(
                    "findings"
                );
            }
        );


    /* DELEGATED TABLE ACTIONS */

    document.addEventListener(
        "click",
        async (event) => {

            const scanButton =
                event.target.closest(
                    "[data-open-scan]"
                );

            if (scanButton) {

                const scanId =
                    scanButton
                        .dataset
                        .openScan;

                await openScan(
                    Number(scanId)
                );

                return;
            }


            const findingButton =
                event.target.closest(
                    "[data-open-finding]"
                );

            if (findingButton) {

                const findingId =
                    findingButton
                        .dataset
                        .openFinding;

                await openFinding(
                    Number(findingId)
                );
            }
        }
    );
}


/* ============================================================
   INITIALIZATION
============================================================ */

async function init() {
    bindEvents();

    if (state.token) {
        await loadCurrentUser();
    } else {
        showAuth();
    }
}

document.addEventListener(
    "DOMContentLoaded",
    init
);

window.deleteAccount = deleteAccount;


document.addEventListener("DOMContentLoaded", () => {
    const closeButton =
        $("close-account-setup");

    if (closeButton) {
        closeButton.addEventListener(
            "click",
            closeAccountSetup
        );
    }

    const testButton =
        $("test-account-connection");

    if (testButton) {
        testButton.addEventListener(
            "click",
            testAccountConnection
        );
    }
});
