/* =========================================================
   TRAFFIC EXPLORER
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    const trafficType = document.getElementById("trafficType");
    const trafficSearch = document.getElementById("trafficSearch");
    const resetButton = document.getElementById("resetTrafficFilters");

    const tableBody = document.getElementById("trafficTableBody");

    const totalRecords = document.getElementById("totalRecords");
    const benignRecords = document.getElementById("benignRecords");
    const attackRecords = document.getElementById("attackRecords");

    const visibleCount = document.getElementById("visibleCount");

    const previousPage = document.getElementById("previousPage");
    const nextPage = document.getElementById("nextPage");
    const paginationNumbers = document.getElementById("paginationNumbers");

    const modal = document.getElementById("trafficModal");
    const modalOverlay = document.getElementById("trafficModalOverlay");
    const closeModal = document.getElementById("closeTrafficModal");
    const closeModalBottom = document.getElementById("closeTrafficModalBottom");

    const modalRecordTitle = document.getElementById("modalRecordTitle");
    const modalRecordLabel = document.getElementById("modalRecordLabel");
    const featureGrid = document.getElementById("trafficFeatureGrid");


    let allRecords = [];
    let filteredRecords = [];

    let currentPage = 1;
    const recordsPerPage = 20;


    /* =====================================================
       LOAD TRAFFIC DATA
    ===================================================== */

    async function loadTrafficData() {

        try {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="traffic-loading">
                        Loading traffic records...
                    </td>
                </tr>
            `;

            const response = await fetch("/api/traffic");

            if (!response.ok) {
                throw new Error("Unable to load traffic data.");
            }

            const data = await response.json();

            allRecords = Array.isArray(data.records)
                ? data.records
                : [];

            filteredRecords = [...allRecords];

            updateStatistics(data);
            renderTable();

        } catch (error) {

            console.error("Traffic Explorer error:", error);

            tableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="traffic-empty">
                        Traffic data is not available yet.
                    </td>
                </tr>
            `;

            totalRecords.textContent = "—";
            benignRecords.textContent = "—";
            attackRecords.textContent = "—";
            visibleCount.textContent = "0";
        }
    }


    /* =====================================================
       STATISTICS
    ===================================================== */

    function updateStatistics(data) {

        const statistics = data.statistics || {};

        totalRecords.textContent =
            formatNumber(statistics.total ?? allRecords.length);

        benignRecords.textContent =
            formatNumber(statistics.benign ?? countBenign(allRecords));

        attackRecords.textContent =
            formatNumber(statistics.attacks ?? countAttacks(allRecords));
    }


    function countBenign(records) {

        return records.filter(record => {
            return String(getLabel(record)).toUpperCase() === "BENIGN";
        }).length;
    }


    function countAttacks(records) {

        return records.filter(record => {
            return String(getLabel(record)).toUpperCase() !== "BENIGN";
        }).length;
    }


    function formatNumber(value) {

        const number = Number(value);

        if (Number.isNaN(number)) {
            return "0";
        }

        return number.toLocaleString();
    }


    /* =====================================================
       FILTERING
    ===================================================== */

    function applyFilters() {

        const selectedType = trafficType.value;
        const searchValue = trafficSearch.value.trim().toLowerCase();

        filteredRecords = allRecords.filter(record => {

            const label = String(getLabel(record)).toUpperCase();

            let typeMatch = true;

            if (selectedType === "BENIGN") {
                typeMatch = label === "BENIGN";
            }

            if (selectedType === "ATTACK") {
                typeMatch = label !== "BENIGN";
            }


            let searchMatch = true;

            if (searchValue !== "") {

                const searchableText = Object.values(record)
                    .join(" ")
                    .toLowerCase();

                searchMatch = searchableText.includes(searchValue);
            }

            return typeMatch && searchMatch;
        });


        currentPage = 1;

        renderTable();
    }


    /* =====================================================
       TABLE RENDERING
    ===================================================== */

    function renderTable() {

        const totalPages = Math.max(
            1,
            Math.ceil(filteredRecords.length / recordsPerPage)
        );

        if (currentPage > totalPages) {
            currentPage = totalPages;
        }


        const startIndex =
            (currentPage - 1) * recordsPerPage;

        const endIndex =
            startIndex + recordsPerPage;

        const pageRecords =
            filteredRecords.slice(startIndex, endIndex);


        visibleCount.textContent =
            filteredRecords.length.toLocaleString();


        tableBody.innerHTML = "";


        if (pageRecords.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="traffic-empty">
                        No traffic records match the selected filters.
                    </td>
                </tr>
            `;

            renderPagination(0);
            return;
        }


        pageRecords.forEach((record, index) => {

            const actualIndex =
                startIndex + index;

            const row =
                document.createElement("tr");

            const label =
                getLabel(record);

            const labelClass =
                String(label).toUpperCase() === "BENIGN"
                    ? "benign"
                    : "attack";


            row.innerHTML = `

                <td>
                    <span class="traffic-record-id">
                        #${getRecordId(record, actualIndex)}
                    </span>
                </td>

                <td class="traffic-number">
                    ${formatValue(
                        getFeature(record, [
                            "Destination Port",
                            "Dst Port",
                            "destination_port"
                        ])
                    )}
                </td>

                <td class="traffic-number">
                    ${formatValue(
                        getFeature(record, [
                            "Flow Duration",
                            "flow_duration"
                        ])
                    )}
                </td>

                <td class="traffic-number">
                    ${formatValue(
                        getFeature(record, [
                            "Total Fwd Packets",
                            "Tot Fwd Pkts",
                            "total_fwd_packets"
                        ])
                    )}
                </td>

                <td class="traffic-number">
                    ${formatValue(
                        getFeature(record, [
                            "Total Backward Packets",
                            "Tot Bwd Pkts",
                            "total_backward_packets"
                        ])
                    )}
                </td>

                <td class="traffic-number">
                    ${formatValue(
                        getFeature(record, [
                            "Flow Bytes/s",
                            "Flow Bytes/s",
                            "flow_bytes_s"
                        ])
                    )}
                </td>

                <td>
                    <span class="traffic-label ${labelClass}">
                        ${escapeHtml(label)}
                    </span>
                </td>

                <td>
                    <button
                        type="button"
                        class="view-record-btn"
                        data-index="${actualIndex}"
                    >
                        View
                    </button>
                </td>
            `;


            tableBody.appendChild(row);
        });


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


        if (filteredRecords.length === 0) {
            return;
        }


        const maxVisiblePages = 5;

        let startPage =
            Math.max(
                1,
                currentPage - Math.floor(maxVisiblePages / 2)
            );

        let endPage =
            Math.min(
                totalPages,
                startPage + maxVisiblePages - 1
            );


        if (
            endPage - startPage + 1
            < maxVisiblePages
        ) {
            startPage =
                Math.max(
                    1,
                    endPage - maxVisiblePages + 1
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
                "page-number" +
                (page === currentPage
                    ? " active"
                    : "");

            button.textContent = page;

            button.addEventListener(
                "click",
                () => {
                    currentPage = page;
                    renderTable();
                }
            );

            paginationNumbers.appendChild(button);
        }
    }


    previousPage.addEventListener(
        "click",
        () => {

            if (currentPage > 1) {
                currentPage--;
                renderTable();
            }
        }
    );


    nextPage.addEventListener(
        "click",
        () => {

            const totalPages =
                Math.ceil(
                    filteredRecords.length /
                    recordsPerPage
                );

            if (currentPage < totalPages) {
                currentPage++;
                renderTable();
            }
        }
    );


    /* =====================================================
       RECORD MODAL
    ===================================================== */

    tableBody.addEventListener(
        "click",
        event => {

            const button =
                event.target.closest(".view-record-btn");

            if (!button) {
                return;
            }

            const index =
                Number(button.dataset.index);

            const record =
                filteredRecords[index];

            if (record) {
                openRecordModal(record, index);
            }
        }
    );


    function openRecordModal(record, index) {

        const label =
            getLabel(record);

        modalRecordTitle.textContent =
            `Record #${getRecordId(record, index)}`;

        modalRecordLabel.textContent =
            label;


        featureGrid.innerHTML = "";


        Object.entries(record).forEach(
            ([key, value]) => {

                const item =
                    document.createElement("div");

                item.className =
                    "traffic-feature-item";


                item.innerHTML = `
                    <span>${escapeHtml(key)}</span>
                    <strong>${escapeHtml(
                        formatValue(value)
                    )}</strong>
                `;


                featureGrid.appendChild(item);
            }
        );


        modal.classList.add("show");
        modal.setAttribute(
            "aria-hidden",
            "false"
        );

        document.body.style.overflow = "hidden";
    }


    function closeTrafficModal() {

        modal.classList.remove("show");

        modal.setAttribute(
            "aria-hidden",
            "true"
        );

        document.body.style.overflow = "";
    }


    closeModal.addEventListener(
        "click",
        closeTrafficModal
    );

    closeModalBottom.addEventListener(
        "click",
        closeTrafficModal
    );

    modalOverlay.addEventListener(
        "click",
        closeTrafficModal
    );


    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Escape" &&
                modal.classList.contains("show")
            ) {
                closeTrafficModal();
            }
        }
    );


    /* =====================================================
       RESET
    ===================================================== */

    resetButton.addEventListener(
        "click",
        () => {

            trafficType.value = "ALL";
            trafficSearch.value = "";

            filteredRecords = [...allRecords];

            currentPage = 1;

            renderTable();
        }
    );


    trafficType.addEventListener(
        "change",
        applyFilters
    );


    trafficSearch.addEventListener(
        "input",
        applyFilters
    );


    /* =====================================================
       DATA HELPERS
    ===================================================== */

    function getLabel(record) {

        return (
            record.Attack_Type ??
            record.attack_type ??
            record.Label ??
            record.label ??
            "UNKNOWN"
        );
    }


    function getRecordId(record, index) {

        return (
            record.record_id ??
            record.Record ??
            record.id ??
            index + 1
        );
    }


    function getFeature(record, possibleNames) {

        for (const name of possibleNames) {

            if (
                Object.prototype.hasOwnProperty.call(
                    record,
                    name
                )
            ) {
                return record[name];
            }
        }

        return "—";
    }


    function formatValue(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return "—";
        }


        if (typeof value === "number") {

            if (!Number.isFinite(value)) {
                return "—";
            }

            return value.toLocaleString(
                undefined,
                {
                    maximumFractionDigits: 4
                }
            );
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

    loadTrafficData();

});