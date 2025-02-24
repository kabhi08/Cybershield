function testFirewall() {
    let url = document.getElementById('firewall-url').value;
    fetch(`/api/test-firewall?url=${encodeURIComponent(url)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('firewall-result').innerText = data.result;
        })
        .catch(error => console.error("Error:", error));
}

function scanPorts() {
    let url = document.getElementById('port-url').value;
    fetch(`/api/scan-ports?url=${encodeURIComponent(url)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('port-result').innerText = data.open_ports.join(", ");
        })
        .catch(error => console.error("Error:", error));
}
