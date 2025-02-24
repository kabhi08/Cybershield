function logIncident() {
    let title = document.getElementById('incident-title').value;
    let description = document.getElementById('incident-description').value;

    fetch('/api/log-incident', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: title, description: description })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('incident-status').innerText = data.message;
        fetchIncidents();
    })
    .catch(error => console.error("Error:", error));
}

function fetchIncidents() {
    fetch('/api/get-incidents')
    .then(response => response.json())
    .then(data => {
        let incidentList = document.getElementById('incident-list');
        incidentList.innerHTML = "";
        data.incidents.forEach(incident => {
            let li = document.createElement('li');
            li.innerText = `📅 ${incident.date} - ${incident.title}: ${incident.description}`;
            incidentList.appendChild(li);
        });
    })
    .catch(error => console.error("Error:", error));
}
