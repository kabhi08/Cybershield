document.addEventListener("DOMContentLoaded", function () {
    // Function to encrypt text using AES
    function encryptText() {
        let text = document.getElementById("text-to-encrypt").value.trim();
        let key = document.getElementById("encryption-key").value.trim();
        
        if (!text || !key) {
            alert("⚠️ Please enter both text and a secret key!");
            return;
        }

        let encrypted = CryptoJS.AES.encrypt(text, key).toString();
        document.getElementById("encrypted-text").textContent = encrypted;
    }

    // Function to decrypt text using AES
    function decryptText() {
        let encryptedText = document.getElementById("text-to-decrypt").value.trim();
        let key = document.getElementById("decryption-key").value.trim();
        
        if (!encryptedText || !key) {
            alert("⚠️ Please enter both encrypted text and the correct secret key!");
            return;
        }

        try {
            let bytes = CryptoJS.AES.decrypt(encryptedText, key);
            let decrypted = bytes.toString(CryptoJS.enc.Utf8);

            if (!decrypted) {
                throw new Error();
            }

            document.getElementById("decrypted-text").textContent = decrypted;
        } catch (error) {
            alert("❌ Invalid encrypted text or wrong key!");
        }
    }

    // Event Listeners
    document.querySelector("button[onclick='encryptText()']").addEventListener("click", encryptText);
    document.querySelector("button[onclick='decryptText()']").addEventListener("click", decryptText);
});
