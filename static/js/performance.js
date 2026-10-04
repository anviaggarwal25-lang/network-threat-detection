/* =========================================================
   MODEL PERFORMANCE
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    const accuracyElement =
        document.getElementById("modelAccuracy");

    const precisionElement =
        document.getElementById("modelPrecision");

    const recallElement =
        document.getElementById("modelRecall");

    const f1Element =
        document.getElementById("modelF1");


    const accuracyBar =
        document.getElementById("accuracyBar");

    const precisionBar =
        document.getElementById("precisionBar");

    const recallBar =
        document.getElementById("recallBar");

    const f1Bar =
        document.getElementById("f1Bar");


    const accuracyBarValue =
        document.getElementById("accuracyBarValue");

    const precisionBarValue =
        document.getElementById("precisionBarValue");

    const recallBarValue =
        document.getElementById("recallBarValue");

    const f1BarValue =
        document.getElementById("f1BarValue");


    const classBody =
        document.getElementById("classPerformanceBody");

    const confusionMatrix =
        document.getElementById("confusionMatrix");


    const modelClasses =
        document.getElementById("modelClasses");

    const datasetRecords =
        document.getElementById("datasetRecords");

    const datasetClasses =
        document.getElementById("datasetClasses");

    const datasetFeatures =
        document.getElementById("datasetFeatures");


    /* =====================================================
       LOAD PERFORMANCE DATA
    ===================================================== */

    async function loadPerformance() {

        try {

            const response =
                await fetch("/api/performance");


            if (!response.ok) {
                throw new Error(
                    "Unable to load model performance."
                );
            }


            const data =
                await response.json();


            updateMetrics(data);

            updateModelInformation(data);

            updateClassPerformance(data);

            updateConfusionMatrix(data);


        } catch (error) {

            console.error(
                "Performance error:",
                error
            );


            showUnavailableState();
        }
    }


    /* =====================================================
       MAIN METRICS
    ===================================================== */

    function updateMetrics(data) {

        const metrics =
            data.metrics || data;


        const accuracy =
            normalizeMetric(
                metrics.accuracy
            );


        const precision =
            normalizeMetric(
                metrics.precision
            );


        const recall =
            normalizeMetric(
                metrics.recall
            );


        const f1 =
            normalizeMetric(
                metrics.f1_score ??
                metrics.f1
            );


        setMetric(
            accuracyElement,
            accuracy
        );

        setMetric(
            precisionElement,
            precision
        );

        setMetric(
            recallElement,
            recall
        );

        setMetric(
            f1Element,
            f1
        );


        setBar(
            accuracyBar,
            accuracyBarValue,
            accuracy
        );

        setBar(
            precisionBar,
            precisionBarValue,
            precision
        );

        setBar(
            recallBar,
            recallBarValue,
            recall
        );

        setBar(
            f1Bar,
            f1BarValue,
            f1
        );
    }


    function normalizeMetric(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return null;
        }


        const number =
            Number(value);


        if (Number.isNaN(number)) {
            return null;
        }


        if (number <= 1) {
            return number * 100;
        }


        return number;
    }


    function setMetric(element, value) {

        if (value === null) {

            element.textContent = "—";

            return;
        }


        element.textContent =
            value.toFixed(2) + "%";
    }


    function setBar(
        bar,
        label,
        value
    ) {

        if (value === null) {

            bar.style.width = "0%";

            label.textContent = "—";

            return;
        }


        const boundedValue =
            Math.max(
                0,
                Math.min(
                    100,
                    value
                )
            );


        bar.style.width =
            boundedValue + "%";


        label.textContent =
            value.toFixed(2) + "%";
    }


    /* =====================================================
       MODEL INFORMATION
    ===================================================== */

    function updateModelInformation(data) {

        const model =
            data.model || {};


        const dataset =
            data.dataset || {};


        document.getElementById(
            "modelAlgorithm"
        ).textContent =
            model.algorithm ??
            "Random Forest";


        document.getElementById(
            "classificationType"
        ).textContent =
            model.classification_type ??
            "Multi-Class";


        document.getElementById(
            "modelFeatures"
        ).textContent =
            model.features ??
            data.features ??
            78;


        const classes =
            model.classes ??
            data.classes ??
            [];


        if (Array.isArray(classes)) {

            modelClasses.textContent =
                classes.length;

            datasetClasses.textContent =
                classes.length;

        } else {

            modelClasses.textContent =
                classes || "—";

            datasetClasses.textContent =
                classes || "—";
        }


        datasetRecords.textContent =
            dataset.test_records ??
            data.test_records ??
            "—";


        datasetFeatures.textContent =
            dataset.features ??
            data.features ??
            78;
    }


    /* =====================================================
       CLASS PERFORMANCE
    ===================================================== */

    function updateClassPerformance(data) {

        const classes =
            data.class_performance ??
            data.classification_report ??
            data.classes_performance ??
            [];


        classBody.innerHTML = "";


        if (
            !Array.isArray(classes) ||
            classes.length === 0
        ) {

            classBody.innerHTML = `
                <tr>
                    <td
                        colspan="5"
                        class="performance-loading"
                    >
                        Per-class evaluation data will appear here.
                    </td>
                </tr>
            `;

            return;
        }


        classes.forEach(item => {

            const row =
                document.createElement("tr");


            row.innerHTML = `

                <td>
                    <span class="class-name">
                        ${escapeHtml(
                            item.class ??
                            item.label ??
                            item.name ??
                            "Unknown"
                        )}
                    </span>
                </td>


                <td>
                    <span class="class-metric">
                        ${formatMetric(
                            item.precision
                        )}
                    </span>
                </td>


                <td>
                    <span class="class-metric">
                        ${formatMetric(
                            item.recall
                        )}
                    </span>
                </td>


                <td>
                    <span class="class-metric">
                        ${formatMetric(
                            item.f1_score ??
                            item.f1
                        )}
                    </span>
                </td>


                <td>
                    <span class="class-support">
                        ${formatNumber(
                            item.support
                        )}
                    </span>
                </td>

            `;


            classBody.appendChild(row);
        });
    }


    function formatMetric(value) {

        const metric =
            normalizeMetric(value);


        if (metric === null) {
            return "—";
        }


        return metric.toFixed(2) + "%";
    }


    function formatNumber(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return "—";
        }


        const number =
            Number(value);


        if (Number.isNaN(number)) {
            return String(value);
        }


        return number.toLocaleString();
    }


    /* =====================================================
       CONFUSION MATRIX
    ===================================================== */

    function updateConfusionMatrix(data) {

        const matrix =
            data.confusion_matrix ??
            data.confusionMatrix;


        const labels =
            data.classes ??
            data.model?.classes ??
            [];


        if (
            !Array.isArray(matrix) ||
            matrix.length === 0
        ) {
            return;
        }


        confusionMatrix.innerHTML = "";


        const table =
            document.createElement("table");


        table.className =
            "matrix-table";


        const headerRow =
            document.createElement("tr");


        const corner =
            document.createElement("th");


        corner.textContent =
            "Actual \\ Predicted";


        headerRow.appendChild(corner);


        labels.forEach(label => {

            const th =
                document.createElement("th");

            th.textContent =
                label;

            headerRow.appendChild(th);
        });


        table.appendChild(headerRow);


        matrix.forEach(
            (rowData, rowIndex) => {

                const row =
                    document.createElement("tr");


                const labelCell =
                    document.createElement("td");


                labelCell.className =
                    "matrix-label";


                labelCell.textContent =
                    labels[rowIndex] ??
                    `Class ${rowIndex + 1}`;


                row.appendChild(labelCell);


                const maxValue =
                    Math.max(
                        ...rowData
                            .map(value =>
                                Number(value) || 0
                            )
                    );


                rowData.forEach(value => {

                    const cell =
                        document.createElement("td");


                    const number =
                        Number(value) || 0;


                    cell.textContent =
                        number.toLocaleString();


                    if (
                        number === maxValue &&
                        number > 0
                    ) {
                        cell.className =
                            "matrix-high";

                    } else if (
                        number > 0
                    ) {
                        cell.className =
                            "matrix-medium";

                    } else {
                        cell.className =
                            "matrix-low";
                    }


                    row.appendChild(cell);
                });


                table.appendChild(row);
            }
        );


        confusionMatrix.appendChild(table);
    }


    /* =====================================================
       UNAVAILABLE STATE
    ===================================================== */

    function showUnavailableState() {

        classBody.innerHTML = `
            <tr>
                <td
                    colspan="5"
                    class="performance-loading"
                >
                    Model evaluation data is not available yet.
                </td>
            </tr>
        `;


        confusionMatrix.innerHTML = `
            <div class="confusion-placeholder">

                <div class="confusion-placeholder-icon">
                    ×
                </div>

                <strong>
                    Evaluation data is not available yet
                </strong>

                <span>
                    The trained model evaluation will be connected
                    when the Flask backend is integrated.
                </span>

            </div>
        `;
    }


    /* =====================================================
       SECURITY
    ===================================================== */

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

    loadPerformance();

});