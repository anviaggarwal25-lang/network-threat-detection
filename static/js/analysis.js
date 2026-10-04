document.addEventListener(
    "DOMContentLoaded",
    function () {

        const button =
            document.getElementById(
                "analyzeButton"
            );


        if (!button) {
            return;
        }


        button.addEventListener(
            "click",
            analyzeTraffic
        );

    }
);


// ============================================================
// ANALYZE TRAFFIC
// ============================================================

async function analyzeTraffic() {

    const button =
        document.getElementById(
            "analyzeButton"
        );


    const scenario =
        document.getElementById(
            "scenarioSelect"
        ).value;


    if (!scenario) {

        showError(
            "Please select a traffic scenario."
        );

        return;
    }


    // Disable button while processing

    button.disabled = true;

    button.textContent =
        "ANALYZING...";


    try {

        const response =
            await fetch(
                "/api/analyze",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            scenario:
                                scenario
                        })

                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            data.error
        ) {

            throw new Error(
                data.error ||
                "Analysis failed."
            );

        }


        displayResult(
            data
        );


    }

    catch (error) {

        console.error(
            "Analysis error:",
            error
        );


        showError(
            error.message
        );

    }

    finally {

        button.disabled = false;

        button.textContent =
            "ANALYZE TRAFFIC";

    }

}


// ============================================================
// DISPLAY ERROR
// ============================================================

function showError(message) {

    const threat =
        document.getElementById(
            "resultThreat"
        );


    const status =
        document.getElementById(
            "resultStatus"
        );


    if (threat) {

        threat.textContent =
            "ERROR";

    }


    if (status) {

        status.textContent =
            message;

    }

}


// ============================================================
// DISPLAY RESULT
// ============================================================

function displayResult(data) {

    const prediction =
        data.prediction;


    const confidence =
        Number(
            data.confidence
        );


    // --------------------------------------------------------
    // THREAT NAME
    // --------------------------------------------------------

    const resultThreat =
        document.getElementById(
            "resultThreat"
        );


    if (resultThreat) {

        resultThreat.textContent =
            prediction;

    }


    // --------------------------------------------------------
    // CONFIDENCE
    // --------------------------------------------------------

    const resultConfidence =
        document.getElementById(
            "resultConfidence"
        );


    if (resultConfidence) {

        resultConfidence.textContent =
            confidence.toFixed(2)
            + "%";

    }


    // --------------------------------------------------------
    // CONFIDENCE BAR
    // --------------------------------------------------------

    const confidenceBar =
        document.getElementById(
            "confidenceBar"
        );


    if (confidenceBar) {

        confidenceBar.style.width =
            Math.min(
                confidence,
                100
            ) + "%";

    }


    // --------------------------------------------------------
    // ACTUAL LABEL
    // --------------------------------------------------------

    const actualLabel =
        document.getElementById(
            "actualLabel"
        );


    if (actualLabel) {

        actualLabel.textContent =
            data.actual_label;

    }


    // --------------------------------------------------------
    // PREDICTED LABEL
    // --------------------------------------------------------

    const predictedLabel =
        document.getElementById(
            "predictedLabel"
        );


    if (predictedLabel) {

        predictedLabel.textContent =
            prediction;

    }


    // --------------------------------------------------------
    // MATCH / MISMATCH
    // --------------------------------------------------------

    const matches =
        data.actual_label ===
        prediction;


    const classificationStatus =
        document.getElementById(
            "classificationStatus"
        );


    if (classificationStatus) {

        classificationStatus.textContent =
            matches
                ? "MATCH"
                : "MISMATCH";

    }


    // --------------------------------------------------------
    // STATUS + RISK
    // --------------------------------------------------------

    const status =
        document.getElementById(
            "resultStatus"
        );


    const risk =
        document.getElementById(
            "resultRisk"
        );


    if (
        prediction ===
        "BENIGN"
    ) {

        if (status) {

            status.textContent =
                "✓ NORMAL TRAFFIC";

        }


        if (risk) {

            risk.textContent =
                "LOW RISK";

            risk.className =
                "badge badge-benign";

        }

    }

    else if (

        prediction ===
        "DDoS"

        ||

        prediction ===
        "DoS"

    ) {

        if (status) {

            status.textContent =
                "⚠ POTENTIAL ATTACK";

        }


        if (risk) {

            risk.textContent =
                "CRITICAL";

            risk.className =
                "badge badge-critical";

        }

    }

    else {

        if (status) {

            status.textContent =
                "⚠ SUSPICIOUS TRAFFIC";

        }


        if (risk) {

            risk.textContent =
                "HIGH RISK";

            risk.className =
                "badge badge-high";

        }

    }


    // --------------------------------------------------------
    // PROBABILITIES
    // --------------------------------------------------------

    displayProbabilities(
        data.probabilities
    );


    // --------------------------------------------------------
    // FEATURES
    // --------------------------------------------------------

    displayFeatures(
        data.features
    );

}


// ============================================================
// DISPLAY CLASS PROBABILITIES
// ============================================================

function displayProbabilities(
    probabilities
) {

    const container =
        document.getElementById(
            "probabilities"
        );


    if (!container) {
        return;
    }


    container.innerHTML = "";


    Object.entries(
        probabilities
    ).forEach(
        ([label, value]) => {


            const percentage =
                Number(value);


            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "probability-row";


            row.innerHTML = `

                <div
                    class="probability-label"
                >
                    ${label}
                </div>


                <div
                    class="progress-container"
                >

                    <div
                        class="progress-bar"
                        style="
                            width:
                            ${Math.min(
                                percentage,
                                100
                            )}%
                        "
                    ></div>

                </div>


                <div
                    class="probability-value"
                >
                    ${percentage.toFixed(2)}%
                </div>

            `;


            container.appendChild(
                row
            );

        }
    );

}


// ============================================================
// DISPLAY NETWORK FEATURES
// ============================================================

function displayFeatures(
    features
) {

    const container =
        document.getElementById(
            "featureGrid"
        );


    if (!container) {
        return;
    }


    container.innerHTML = "";


    Object.entries(
        features
    ).forEach(
        ([name, value]) => {


            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "feature-item";


            item.innerHTML = `

                <div
                    class="feature-name"
                    title="${name}"
                >
                    ${name}
                </div>


                <div
                    class="feature-value"
                >
                    ${formatValue(value)}
                </div>

            `;


            container.appendChild(
                item
            );

        }
    );

}


// ============================================================
// FORMAT VALUES
// ============================================================

function formatValue(
    value
) {

    if (
        typeof value ===
        "number"
    ) {

        if (
            Number.isInteger(value)
        ) {

            return value.toLocaleString();

        }


        return value.toFixed(4);

    }


    return value;

}