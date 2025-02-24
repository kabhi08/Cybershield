function generateTOTP() {
    let secret = document.getElementById('secret-key').value;
    fetch(`/api/generate-2fa?secret=${encodeURIComponent(secret)}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('totp-code').innerText = data.code;
        })
        .catch(error => console.error("Error:", error));
}

function checkSessions() {
    fetch(`/api/check-sessions`)
        .then(response => response.json())
        .then(data => {
            let sessionList = document.getElementById('session-list');
            sessionList.innerHTML = "";
            data.sessions.forEach(session => {
                let li = document.createElement('li');
                li.innerText = `User: ${session.user}, IP: ${session.ip}, Last Active: ${session.last_active}`;
                sessionList.appendChild(li);
            });
        })
        .catch(error => console.error("Error:", error));
}
