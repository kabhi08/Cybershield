function generatePassword() {
    let length = document.getElementById("password-length").value;
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    document.getElementById("generated-password").innerText = password;

    // Log usage in the database
    logToolUsage("Password Generator");
}

function checkPasswordStrength() {
    let password = document.getElementById("password-input").value;
    let strength = "Weak";

    if (password.length > 8) strength = "Medium";
    if (password.match(/[A-Z]/) && password.match(/[0-9]/) && password.length > 12) strength = "Strong";

    document.getElementById("password-strength").innerText = strength;

    // Log usage in the database
    logToolUsage("Password Strength Checker");
}

// Function to log tool usage
function logToolUsage(toolName) {
    let businessName = prompt("Enter the business or website name:");
    if (!businessName) return;

    let policyId = 1; // Change dynamically based on the tool's policy

    fetch("/log_tool_usage", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            business_name: businessName,
            policy_id: policyId,
            tool_name: toolName
        })
    })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error("Error logging tool usage:", error));
}
