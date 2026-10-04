document.addEventListener("DOMContentLoaded", () => {
    loadOverview();
});


async function loadOverview() {

    console.log("Loading overview data...");

    try {

        const response = await fetch("/api/overview");

        console.log("API response:", response.status);

        if (!response.ok) {
            throw new Error(
                `API request failed: ${response.status}`
            );
        }

        const data = await response.json();

        console.log("Overview data:", data);


        // -------------------------------
        // METRIC CARDS
        // -------------------------------

        document.getElementById("totalFlows").textContent =
            Number(data.total).toLocaleString();

        document.getElementById("benignFlows").textContent =
            Number(data.benign).toLocaleString();

        document.getElementById("attackFlows").textContent =
            Number(data.attacks).toLocaleString();


        // -------------------------------
        // THREAT DISTRIBUTION
        // -------------------------------

        const container =
            document.getElementById("distribution");

        container.innerHTML = "";


        const labels = [
            "BENIGN",
            "BRUTE FORCE",
            "DDoS",
            "DoS",
            "PORT SCAN"
        ];


        labels.forEach(label => {

            const count =
                Number(data.distribution[label] || 0);

            const percentage =
                (count / data.total) * 100;


            const item =
                document.createElement("div");

            item.className =
                "distribution-item";


            item.innerHTML = `

                <div class="distribution-name">
                    ${label}
                </div>

                <div class="progress-container">

                    <div
                        class="progress-bar"
                        style="width: ${percentage}%"
                    ></div>

                </div>

                <div class="distribution-count">
                    ${count.toLocaleString()}
                </div>

            `;


            container.appendChild(item);

        });


        console.log(
            "Overview loaded successfully."
        );

    }


    catch (error) {

        console.error(
            "Overview loading failed:",
            error
        );


        document.getElementById(
            "distribution"
        ).innerHTML = `

            <div class="empty-state">

                <div class="empty-state-title">
                    Unable to load dataset
                </div>

                <div class="empty-state-description">
                    Check the browser console for details.
                </div>

            </div>

        `;

    }

}