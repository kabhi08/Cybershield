// Scroll to Top Button
window.onscroll = function() {
    let btn = document.querySelector(".back-to-top");
    if (document.documentElement.scrollTop > 300) {
        btn.style.opacity = "1";
        btn.style.pointerEvents = "auto";
    } else {
        btn.style.opacity = "0";
        btn.style.pointerEvents = "none";
    }
};

// Scroll to Top Function
document.querySelector(".back-to-top").addEventListener("click", function() {
    window.scrollTo({ top: 0, behavior: "smooth" });
});

// Scroll Indicator Animation
document.querySelector('.scroll-down').addEventListener('click', function() {
    document.querySelector('.policy-container').scrollIntoView({ behavior: 'smooth' });
});

// Navbar Scroll Effect
window.addEventListener("scroll", function() {
    let navbar = document.querySelector(".navbar");
    if (window.scrollY > 50) {
        navbar.style.background = "rgba(0, 0, 0, 0.9)";
    } else {
        navbar.style.background = "rgba(0, 0, 0, 0.7)";
    }
});

// Redirect to Policy Page with Authentication Check
document.querySelector("a[href$='policy']").addEventListener("click", function(event) {
    fetch('/policy', { method: 'GET' })
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;  // Redirect to login if not authenticated
            }
        });
});
