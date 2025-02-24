document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("form");
    const hackingProcess = document.getElementById("hacking-process");
    const resultMessage = document.getElementById("result-message");

    form.addEventListener("submit", function (event) {
        event.preventDefault();  

        const businessName = document.getElementById("business_name").value.trim();
        const toolName = document.getElementById("tool_name").value;

        if (!businessName || !toolName) {
            alert("Please enter a business name and select a tool.");
            return;
        }

        hackingProcess.style.display = "block";
        resultMessage.innerHTML = "";

        let counter = 0;
        const processingTexts = [
            "Scanning website...",
            "Checking security protocols...",
            "Applying security policy...",
            "Encrypting data...",
            "Verifying compliance...",
            "Finalizing protection..."
        ];

        const interval = setInterval(() => {
            hackingProcess.innerHTML = processingTexts[counter];
            counter++;
            if (counter >= processingTexts.length) {
                clearInterval(interval);

                // Send AJAX request to Flask
                fetch(window.location.href, {
                    method: "POST",
                    body: new FormData(form)
                })
                .then(response => response.json())
                .then(data => {
                    console.log("Server Response:", data); // Debugging line

                    hackingProcess.style.display = "none";
                    resultMessage.innerHTML = `<span class='${data.status}'>${data.message}</span>`;
                })
                .catch(error => {
                    console.error("Fetch Error:", error); // Debugging line
                    hackingProcess.style.display = "none";
                    resultMessage.innerHTML = "<span class='error'>❌ Error checking the website.</span>";
                });
            }
        }, 1500);
    });
});
