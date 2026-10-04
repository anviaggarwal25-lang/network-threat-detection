/* =========================================================
   ALERTS PAGE
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    const severityFilter =
        document.getElementById("alertSeverity");

    const searchInput =
        document.getElementById("alertSearch");

    const resetButton =
        document.getElementById("resetAlertFilters");

    const tableBody =
        document.getElementById("alertsTableBody");

    const totalAlerts =
        document.getElementById("totalAlerts");

    const criticalAlerts =
        document.getElementById("criticalAlerts");

    const highAlerts =
        document.getElementById("highAlerts");

    const mediumLowAlerts =
        document.getElementById("mediumLowAlerts");

    const visibleAlertCount =
        document.getElementById("visibleAlertCount");

    const previousPage =
        document.getElementById("previousAlertPage");

    const nextPage =
        document.getElementById("nextAlertPage");

    const paginationNumbers =
        document.getElementById("alertPaginationNumbers");


    /* MODAL */

    const modal =
        document.getElementById("alertModal");

    const modalOverlay =
        document.getElementById("alertModalOverlay");

    const closeModal =
        document.getElementById("closeAlertModal");

    const closeModalBottom =
        document.getElementById("closeAlertModalBottom");

    const modalAlertTitle =
        document.getElementById("modalAlertTitle");

    const modalAlertSeverity =
        document.getElementById("modalAlertSeverity");

    const modalThreatType =
        document.getElementById("modalThreatType");

    const modalConfidence =
        document.getElementById("modalConfidence");

    const modalRecord =
        document.getElementById("modalRecord");

    const modalStatus =
        document.getElementById("modalStatus");

    const modalSource =
        document.getElementById("modalSource");

    const modalDestination =
        document.getElementById("modalDestination");

    const modalDescription =
        document.getElementById("modalDescription");


    let allAlerts = [];
    let filteredAlerts = [];

    let currentPage = 1;

    const alertsPerPage = 15;


    /* =====================================================
       LOAD ALERTS
    ===================================================== */

    async function loadAlerts() {

        try {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="alerts-loading">
                        Loading security alerts...
                    </td>
                </tr>
            `;


            const response =
                await fetch("/api/alerts");


            if (!response.ok) {
                throw new Error(
                    "Unable to load alerts."
                );
            }


            const data =
                await response.json();


            allAlerts =
                Array.isArray(data.alerts)
                    ? data.alerts
                    : [];


            filteredAlerts =
                [...allAlerts];


            updateStatistics(data);

            renderAlerts();


        } catch (error) {

            console.error(
                "Alerts error:",
                error
            );


            tableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="alerts-empty">
                        Alert data is not available yet.
                    </td>
                </tr>
            `;


            totalAlerts.textContent = "—";
            criticalAlerts.textContent = "—";
            highAlerts.textContent = "—";
            mediumLowAlerts.textContent = "—";
            visibleAlertCount.textContent = "0";
        }
    }


    /* =====================================================
       STATISTICS
    ===================================================== */

    function updateStatistics(data) {

        const stats =
            data.statistics || {};


        totalAlerts.textContent =
            formatNumber(
                stats.total ?? allAlerts.length
            );


        criticalAlerts.textContent =
            formatNumber(
                stats.critical ??
                countSeverity("CRITICAL")
            );


        highAlerts.textContent =
            formatNumber(
                stats.high ??
                countSeverity("HIGH")
            );


        mediumLowAlerts.textContent =
            formatNumber(
                stats.medium_low ??
                countMediumLow()
            );
    }


    function countSeverity(severity) {

        return allAlerts.filter(
            alert =>
                getSeverity(alert) === severity
        ).length;
    }


    function countMediumLow() {

        return allAlerts.filter(alert => {

            const severity =
                getSeverity(alert);

            return (
                severity === "MEDIUM" ||
                severity === "LOW"
            );

        }).length;
    }


    function formatNumber(value) {

        const number =
            Number(value);

        if (Number.isNaN(number)) {
            return "0";
        }

        return number.toLocaleString();
    }


    /* =====================================================
       FILTERS
    ===================================================== */

    function applyFilters() {

        const selectedSeverity =
            severityFilter.value;

        const search =
            searchInput.value
                .trim()
                .toLowerCase();


        filteredAlerts =
            allAlerts.filter(alert => {

                const severity =
                    getSeverity(alert);


                let severityMatch = true;


                if (
                    selectedSeverity !== "ALL"
                ) {
                    severityMatch =
                        severity === selectedSeverity;
                }


                let searchMatch = true;


                if (search !== "") {

                    const searchableText =
                        Object.values(alert)
                            .join(" ")
                            .toLowerCase();


                    searchMatch =
                        searchableText.includes(
                            search
                        );
                }


                return (
                    severityMatch &&
                    searchMatch
                );
            });


        currentPage = 1;

        renderAlerts();
    }


    /* =====================================================
       RENDER ALERT TABLE
    ===================================================== */

    function renderAlerts() {

        const totalPages =
            Math.max(
                1,
                Math.ceil(
                    filteredAlerts.length /
                    alertsPerPage
                )
            );


        if (
            currentPage > totalPages
        ) {
            currentPage = totalPages;
        }


        const startIndex =
            (currentPage - 1) *
            alertsPerPage;


        const endIndex =
            startIndex +
            alertsPerPage;


        const pageAlerts =
            filteredAlerts.slice(
                startIndex,
                endIndex
            );


        visibleAlertCount.textContent =
            filteredAlerts.length
                .toLocaleString();


        tableBody.innerHTML = "";


        if (pageAlerts.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td
                        colspan="7"
                        class="alerts-empty"
                    >
                        No alerts match the selected filters.
                    </td>
                </tr>
            `;

            renderPagination(0);

            return;
        }


        pageAlerts.forEach(
            (alert, index) => {

                const actualIndex =
                    startIndex + index;


                const severity =
                    getSeverity(alert);


                const severityClass =
                    severity.toLowerCase();


                const status =
                    getStatus(alert);


                const statusClass =
                    status
                        .toLowerCase()
                        .replace(/\s+/g, "-");


                const row =
                    document.createElement("tr");


                row.innerHTML = `

                    <td>
                        <span class="alert-id">
                            #${escapeHtml(
                                getAlertId(
                                    alert,
                                    actualIndex
                                )
                            )}
                        </span>
                    </td>


                    <td>
                        <span class="alert-threat-type">
                            ${escapeHtml(
                                getThreatType(alert)
                            )}
                        </span>
                    </td>


                    <td>
                        <span
                            class="alert-severity ${severityClass}"
                        >
                            ${escapeHtml(severity)}
                        </span>
                    </td>


                    <td>
                        <span class="alert-confidence">
                            ${formatConfidence(
                                getConfidence(alert)
                            )}
                        </span>
                    </td>


                    <td>
                        <span class="alert-confidence">
                            #${escapeHtml(
                                getRecordId(alert)
                            )}
                        </span>
                    </td>


                    <td>
                        <span
                            class="alert-status ${statusClass}"
                        >
                            ${escapeHtml(status)}
                        </span>
                    </td>


                    <td>
                        <button
                            type="button"
                            class="view-alert-btn"
                            data-index="${actualIndex}"
                        >
                            View
                        </button>
                    </td>

                `;


                tableBody.appendChild(row);
            }
        );


        renderPagination(totalPages);
    }


    /* =====================================================
       PAGINATION
    ===================================================== */

    function renderPagination(totalPages) {

        paginationNumbers.innerHTML = "";


        previousPage.disabled =
            currentPage <= 1;


        nextPage.disabled =
            currentPage >= totalPages;


        if (
            filteredAlerts.length === 0
        ) {
            return;
        }


        const maxPages = 5;


        let startPage =
            Math.max(
                1,
                currentPage -
                Math.floor(maxPages / 2)
            );


        let endPage =
            Math.min(
                totalPages,
                startPage + maxPages - 1
            );


        if (
            endPage - startPage + 1 <
            maxPages
        ) {

            startPage =
                Math.max(
                    1,
                    endPage - maxPages + 1
                );
        }


        for (
            let page = startPage;
            page <= endPage;
            page++
        ) {

            const button =
                document.createElement("button");


            button.type = "button";

            button.className =
                "alert-page-number" +
                (
                    page === currentPage
                        ? " active"
                        : ""
                );


            button.textContent = page;


            button.addEventListener(
                "click",
                () => {

                    currentPage = page;

                    renderAlerts();
                }
            );


            paginationNumbers.appendChild(
                button
            );
        }
    }


    previousPage.addEventListener(
        "click",
        () => {

            if (currentPage > 1) {

                currentPage--;

                renderAlerts();
            }
        }
    );


    nextPage.addEventListener(
        "click",
        () => {

            const totalPages =
                Math.ceil(
                    filteredAlerts.length /
                    alertsPerPage
                );


            if (
                currentPage <
                totalPages
            ) {

                currentPage++;

                renderAlerts();
            }
        }
    );


    /* =====================================================
       VIEW ALERT
    ===================================================== */

    tableBody.addEventListener(
        "click",
        event => {

            const button =
                event.target.closest(
                    ".view-alert-btn"
                );


            if (!button) {
                return;
            }


            const index =
                Number(
                    button.dataset.index
                );


            const alert =
                filteredAlerts[index];


            if (alert) {
                openAlertModal(alert);
            }
        }
    );


    function openAlertModal(alert) {

        const severity =
            getSeverity(alert);


        modalAlertTitle.textContent =
            `Alert #${getAlertId(alert)}`;


        modalAlertSeverity.textContent =
            severity;


        modalThreatType.textContent =
            getThreatType(alert);


        modalConfidence.textContent =
            formatConfidence(
                getConfidence(alert)
            );


        modalRecord.textContent =
            `#${getRecordId(alert)}`;


        modalStatus.textContent =
            getStatus(alert);


        modalSource.textContent =
            getSource(alert);


        modalDestination.textContent =
            getDestination(alert);


        modalDescription.textContent =
            getDescription(alert);


        modal.classList.add("show");

        modal.setAttribute(
            "aria-hidden",
            "false"
        );


        document.body.style.overflow =
            "hidden";
    }


    function closeAlertModal() {

        modal.classList.remove("show");

        modal.setAttribute(
            "aria-hidden",
            "true"
        );


        document.body.style.overflow =
            "";
    }


    closeModal.addEventListener(
        "click",
        closeAlertModal
    );


    closeModalBottom.addEventListener(
        "click",
        closeAlertModal
    );


    modalOverlay.addEventListener(
        "click",
        closeAlertModal
    );


    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Escape" &&
                modal.classList.contains(
                    "show"
                )
            ) {
                closeAlertModal();
            }
        }
    );


    /* =====================================================
       RESET
    ===================================================== */

    resetButton.addEventListener(
        "click",
        () => {

            severityFilter.value =
                "ALL";

            searchInput.value =
                "";

            filteredAlerts =
                [...allAlerts];

            currentPage = 1;

            renderAlerts();
        }
    );


    severityFilter.addEventListener(
        "change",
        applyFilters
    );


    searchInput.addEventListener(
        "input",
        applyFilters
    );


    /* =====================================================
       DATA HELPERS
    ===================================================== */

    function getAlertId(alert, index = 1) {

        return (
            alert.alert_id ??
            alert.Alert_ID ??
            alert.id ??
            `ALT-${String(index + 1)
                .padStart(4, "0")}`
        );
    }


    function getRecordId(alert) {

        return (
            alert.record_id ??
            alert.Record ??
            alert.dataset_record ??
            alert.dataset_id ??
            alert.id ??
            "—"
        );
    }


    function getThreatType(alert) {

        return (
            alert.threat_type ??
            alert.Threat_Type ??
            alert.attack_type ??
            alert.Attack_Type ??
            alert.label ??
            alert.Label ??
            "Unknown"
        );
    }


    function getSeverity(alert) {

        const value =
            String(
                alert.severity ??
                alert.Severity ??
                ""
            ).toUpperCase();


        if (
            value === "CRITICAL" ||
            value === "HIGH" ||
            value === "MEDIUM" ||
            value === "LOW"
        ) {
            return value;
        }


        const threat =
            getThreatType(alert)
                .toUpperCase();


        if (
            threat === "DDOS" ||
            threat === "DOS"
        ) {
            return "CRITICAL";
        }


        if (
            threat === "BRUTE FORCE" ||
            threat === "PORT SCAN"
        ) {
            return "HIGH";
        }


        return "LOW";
    }


    function getConfidence(alert) {

        return (
            alert.confidence ??
            alert.probability ??
            alert.model_probability ??
            alert.Model_Probability ??
            "—"
        );
    }


    function getStatus(alert) {

        return (
            alert.status ??
            alert.Status ??
            "NEW"
        );
    }


    function getSource(alert) {

        return (
            alert.source ??
            alert.Source ??
            alert.source_ip ??
            alert["Source IP"] ??
            "—"
        );
    }


    function getDestination(alert) {

        return (
            alert.destination ??
            alert.Destination ??
            alert.destination_ip ??
            alert["Destination IP"] ??
            "—"
        );
    }


    function getDescription(alert) {

        return (
            alert.description ??
            alert.Description ??
            `The model identified ${getThreatType(alert)} traffic requiring review.`
        );
    }


    function formatConfidence(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return "—";
        }


        const number =
            Number(value);


        if (
            !Number.isNaN(number)
        ) {

            if (number <= 1) {
                return (
                    number * 100
                ).toFixed(2) + "%";
            }


            return number.toFixed(2) + "%";
        }


        return String(value);
    }


    function escapeHtml(value) {

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    /* =====================================================
       INITIAL LOAD
    ===================================================== */

    loadAlerts();

});