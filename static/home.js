// Scroll to Top Button Visibility
window.addEventListener("scroll", function() {
    let btn = document.querySelector(".back-to-top");
    if (window.scrollY > 300) {
        btn.classList.add("visible");
    } else {
        btn.classList.remove("visible");
    }
});

// Smooth Scroll to Top
document.querySelector(".back-to-top").addEventListener("click", function() {
    window.scrollTo({ top: 0, behavior: "smooth" });
});
