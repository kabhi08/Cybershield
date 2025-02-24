function checkIP() {
    let ip = document.getElementById('ip-address').value;
    fetch(`/api/check-ip?ip=${encodeURIComponent(ip)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('ip-result').innerText = data.result;
        })
        .catch(error => console.error("Error:", error));
}

function checkDarkWeb() {
    let email = document.getElementById('email-check').value;
    fetch(`/api/check-dark-web?email=${encodeURIComponent(email)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('email-result').innerText = data.result;
        })
        .catch(error => console.error("Error:", error));
}
