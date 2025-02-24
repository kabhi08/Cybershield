document.addEventListener("DOMContentLoaded", function () {
    let applyBtn = document.getElementById("apply-policy-btn");
    let modal = document.getElementById("policy-modal");
    let closeModal = document.querySelector(".close");
    let confirmApply = document.getElementById("confirm-apply");
    let useCaseInput = document.getElementById("use-case");

    applyBtn.addEventListener("click", function () {
        modal.style.display = "block";
    });

    closeModal.addEventListener("click", function () {
        modal.style.display = "none";
    });

    window.onclick = function (event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };

    confirmApply.addEventListener("click", function () {
        let useCase = useCaseInput.value.trim();
        if (useCase) {
            alert(`🌟 Success! The "${document.title}" policy has been successfully applied to ${useCase}. 
            
Your business is now secured with industry-standard cybersecurity measures. 🚀`);
            modal.style.display = "none";
            useCaseInput.value = "";
        } else {
            alert("⚠️ Please enter where you want to apply this policy.");
        }
    });
});
