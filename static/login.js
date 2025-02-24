// Select elements
const openBtn = document.getElementById("openBtn");
const closeBtn = document.getElementById("closeBtn");
const loginPopup = document.getElementById("loginPopup");

// Open Login Popup
openBtn.addEventListener("click", () => {
    loginPopup.classList.add("show-popup");
});

// Close Login Popup
closeBtn.addEventListener("click", () => {
    loginPopup.classList.remove("show-popup");
});

// Close on outside click
window.addEventListener("click", (e) => {
    if (e.target === loginPopup) {
        loginPopup.classList.remove("show-popup");
    }
});
