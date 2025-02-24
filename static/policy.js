// Scroll to Top Button Visibility
window.onscroll = function () {
    let btn = document.querySelector(".back-to-top");
    if (document.documentElement.scrollTop > 300) {
        btn.style.opacity = "1";
        btn.style.pointerEvents = "auto";
    } else {
        btn.style.opacity = "0";
        btn.style.pointerEvents = "none";
    }
};

// Smooth Scroll to Top
function scrollToTop() {
    window.scrollTo({ top: 0, behavior: "smooth" });
}

// Policy Data (You can replace this with a backend call)
const policies = {
    "cybersecurity": {
        title: "Cyber Security Policy",
        description: "A policy ensuring the safety of data and preventing cyber threats.",
        advantages: ["Protects sensitive data", "Reduces cyber attack risks", "Ensures compliance"],
        disadvantages: ["Requires constant updates", "Can be expensive to implement"]
    },
    "dataprivacy": {
        title: "Data Privacy Policy",
        description: "Guidelines for handling personal and confidential information.",
        advantages: ["Prevents data breaches", "Builds trust with users", "Ensures legal compliance"],
        disadvantages: ["May limit data access", "Requires frequent updates"]
    }
};

// Handle Policy Clicks & Show Modal
document.addEventListener("DOMContentLoaded", function () {
    let policyCards = document.querySelectorAll(".policy-card");

    // Create Modal Element
    let modal = document.createElement("div");
    modal.classList.add("modal");
    modal.innerHTML = `
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2 id="modal-title"></h2>
            <p id="modal-description"></p>

            <h3>Advantages</h3>
            <ul id="modal-advantages"></ul>

            <h3>Disadvantages</h3>
            <ul id="modal-disadvantages"></ul>

            <label for="use-case">Where do you want to use this policy?</label>
            <input type="text" id="use-case" placeholder="Enter website or business name">
            <button id="apply-policy" class="btn-apply">Apply Policy</button>
        </div>
    `;
    document.body.appendChild(modal);

    let modalTitle = document.getElementById("modal-title");
    let modalDescription = document.getElementById("modal-description");
    let modalAdvantages = document.getElementById("modal-advantages");
    let modalDisadvantages = document.getElementById("modal-disadvantages");
    let modalClose = modal.querySelector(".close");
    let applyButton = document.getElementById("apply-policy");
    let useCaseInput = document.getElementById("use-case");

    // Listen for clicks on "Read More" buttons
    document.addEventListener("click", function (event) {
        let target = event.target;

        // Check if the clicked element is a "Read More" button inside .policy-card
        if (target.classList.contains("read-more")) {
            let card = target.closest(".policy-card"); // Get the closest policy card
            let policyKey = card.getAttribute("data-policy"); // Get policy identifier

            if (!policyKey || !policies[policyKey]) {
                console.warn("Invalid policy key:", policyKey); // Log warning instead of showing error
                return; // Do nothing if policy is not found
            }

            let policy = policies[policyKey];

            // Update modal content
            modalTitle.innerText = policy.title;
            modalDescription.innerText = policy.description;

            // Populate advantages
            modalAdvantages.innerHTML = "";
            policy.advantages.forEach(adv => {
                let li = document.createElement("li");
                li.textContent = adv;
                modalAdvantages.appendChild(li);
            });

            // Populate disadvantages
            modalDisadvantages.innerHTML = "";
            policy.disadvantages.forEach(disadv => {
                let li = document.createElement("li");
                li.textContent = disadv;
                modalDisadvantages.appendChild(li);
            });

            // Show modal
            modal.style.display = "block";
        }
    });

    // Close modal
    modalClose.addEventListener("click", function () {
        modal.style.display = "none";
    });

    // Close modal if clicking outside
    window.onclick = function (event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };

    // Apply policy action
    applyButton.addEventListener("click", function () {
        let useCase = useCaseInput.value.trim();
        if (useCase) {
            alert(`Policy applied successfully to ${useCase}!`);
            modal.style.display = "none";
            useCaseInput.value = "";
        } else {
            alert("Please enter where you want to use this policy.");
        }
    });
});
