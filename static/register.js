document.addEventListener("DOMContentLoaded", function () {
    console.log("Registration page loaded.");

    let popup = document.getElementById("registerPopup");
    let exploreBtn = document.getElementById("exploreBtn");
    let form = document.querySelector("form");
    let usernameInput = document.getElementById("username");
    let emailInput = document.getElementById("email");
    let passwordInput = document.getElementById("password");

    // Open Popup
    exploreBtn.addEventListener("click", function () {
        popup.classList.add("show");
    });

    // Close Popup
    function closePopup() {
        popup.classList.remove("show");
    }

    // Attach close function to global scope
    window.closePopup = closePopup;

    // Real-time validation
    usernameInput.addEventListener("input", validateUsername);
    emailInput.addEventListener("input", validateEmail);
    passwordInput.addEventListener("input", validatePassword);

    // Form validation on submit
    form.addEventListener("submit", function (event) {
        let valid = true;

        if (!validateUsername()) valid = false;
        if (!validateEmail()) valid = false;
        if (!validatePassword()) valid = false;

        if (!valid) {
            event.preventDefault();
        } else {
            alert("✅ Registration successful!");
        }
    });

    function validateUsername() {
        let username = usernameInput.value.trim();
        if (username.length < 3) {
            setError(usernameInput, "⚠ Username must be at least 3 characters long.");
            return false;
        } else {
            clearError(usernameInput);
            return true;
        }
    }

    function validateEmail() {
        let email = emailInput.value.trim();
        let emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        if (!emailPattern.test(email)) {
            setError(emailInput, "⚠ Enter a valid email address.");
            return false;
        } else {
            clearError(emailInput);
            return true;
        }
    }

    function validatePassword() {
        let password = passwordInput.value.trim();
        let passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;

        if (!passwordPattern.test(password)) {
            setError(passwordInput, "⚠ Password must be at least 6 characters with letters & numbers.");
            return false;
        } else {
            clearError(passwordInput);
            return true;
        }
    }

    function setError(input, message) {
        input.style.border = "2px solid red";
        let errorText = input.nextElementSibling;
        if (!errorText || !errorText.classList.contains("error-text")) {
            errorText = document.createElement("small");
            errorText.classList.add("error-text");
            errorText.style.color = "red";
            errorText.style.display = "block";
            input.parentNode.insertBefore(errorText, input.nextSibling);
        }
        errorText.innerText = message;
    }

    function clearError(input) {
        input.style.border = "2px solid green";
        let errorText = input.nextElementSibling;
        if (errorText && errorText.classList.contains("error-text")) {
            errorText.remove();
        }
    }
});
