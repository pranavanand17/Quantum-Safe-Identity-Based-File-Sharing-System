(() => {
    const button = document.getElementById("pair-button");
    if (!button) return;

    const buttonText = document.getElementById("pair-button-text");
    const qrImage = document.getElementById("qr-image");
    const placeholder = document.getElementById("qr-placeholder");
    const countdown = document.getElementById("countdown");
    const deviceStatus = document.getElementById("device-status");
    const pairingState = document.getElementById("pairing-state");
    const message = document.getElementById("pair-message");

    let statusTimer = null;
    let countdownTimer = null;
    let expiresAt = 0;
    let activeToken = null;

    function setMessage(text) {
        message.textContent = text;
    }

    function formatTime(seconds) {
        const safe = Math.max(0, seconds);
        return `${String(Math.floor(safe / 60)).padStart(2, "0")}:${String(safe % 60).padStart(2, "0")}`;
    }

    function stopTimers() {
        clearInterval(statusTimer);
        clearInterval(countdownTimer);
        statusTimer = null;
        countdownTimer = null;
    }

    function startCountdown() {
        clearInterval(countdownTimer);
        const update = () => {
            const remaining = Math.ceil(expiresAt - Date.now() / 1000);
            countdown.textContent = formatTime(remaining);

            if (remaining <= 0) {
                clearInterval(countdownTimer);
                if (pairingState.textContent !== "PAIRED") {
                    pairingState.textContent = "EXPIRED";
                    deviceStatus.textContent = "Code expired";
                    setMessage("This code expired. Generate a new one to pair a device.");
                    qrImage.classList.add("hidden");
                    placeholder.classList.remove("hidden");
                }
            }
        };
        update();
        countdownTimer = setInterval(update, 1000);
    }

    async function checkStatus() {
        if (!activeToken) return;

        try {
            const response = await fetch(`/api/status/${encodeURIComponent(activeToken)}`, {
                cache: "no-store"
            });
            const data = await response.json();

            if (data.status === "paired") {
                stopTimers();
                countdown.textContent = "COMPLETE";
                deviceStatus.textContent = data.device_name || "Phone connected";
                pairingState.textContent = "PAIRED";
                pairingState.classList.add("is-paired");
                buttonText.textContent = "Pair another device";
                setMessage("Device paired successfully. The next milestone is phone-side transfer approval.");
            } else if (data.status === "expired") {
                stopTimers();
                pairingState.textContent = "EXPIRED";
                deviceStatus.textContent = "Code expired";
                qrImage.classList.add("hidden");
                placeholder.classList.remove("hidden");
                setMessage("This code expired. Generate a new one to pair a device.");
                buttonText.textContent = "Generate new pairing code";
            }
        } catch {
            setMessage("Connection interrupted. Check that this page can reach the local server.");
        }
    }

    button.addEventListener("click", async () => {
        stopTimers();
        button.disabled = true;
        buttonText.textContent = "Generating…";
        pairingState.textContent = "PREPARING";
        pairingState.classList.remove("is-paired");
        deviceStatus.textContent = "Waiting for device";
        qrImage.classList.add("hidden");
        placeholder.classList.remove("hidden");
        countdown.textContent = "02:00";

        try {
            const response = await fetch("/api/pairing", {
                method: "POST",
                headers: {"Content-Type": "application/json"}
            });
            const data = await response.json();

            if (!response.ok) throw new Error(data.error || "Could not create pairing session.");

            activeToken = data.token;
            expiresAt = Date.now() / 1000 + data.expires_in;

            qrImage.src = `${data.qr_url}?t=${Date.now()}`;
            qrImage.onload = () => {
                qrImage.classList.remove("hidden");
                placeholder.classList.add("hidden");
            };
            qrImage.onerror = () => setMessage("QR code could not be loaded. Try generating another.");

            pairingState.textContent = "AWAITING DEVICE";
            buttonText.textContent = "Generate new pairing code";
            setMessage("Scan this code using your phone camera. Both devices must be on the same Wi-Fi.");
            startCountdown();
            statusTimer = setInterval(checkStatus, 1500);
        } catch (error) {
            pairingState.textContent = "ERROR";
            buttonText.textContent = "Try again";
            setMessage(error.message || "Unable to generate pairing code.");
        } finally {
            button.disabled = false;
        }
    });
})();
