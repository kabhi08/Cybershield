function checkPhishing() {
    let url = document.getElementById('phishing-url').value;
    fetch(`/api/check-phishing?url=${encodeURIComponent(url)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('phishing-result').innerText = data.result;
        })
        .catch(error => console.error("Error:", error));
}

function analyzeLogs() {
    let fileInput = document.getElementById('log-file');
    let file = fileInput.files[0];

    if (!file) {
        alert("Please upload a log file first.");
        return;
    }

    let formData = new FormData();
    formData.append("file", file);

    fetch('/api/analyze-logs', {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('log-analysis-result').innerText = data.result;
    })
    .catch(error => console.error("Error:", error));
}
