function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function animatePipeline(selector, delay = 380) {
  const items = document.querySelectorAll(selector);
  items.forEach((item) => item.classList.remove("active"));
  for (const item of items) {
    item.classList.add("active");
    await sleep(delay);
  }
}

function showModal(id) {
  document.getElementById(id).classList.remove("hidden");
}

function hideModal(id) {
  document.getElementById(id).classList.add("hidden");
}

const sendForm = document.getElementById("send-form");
if (sendForm) {
  sendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorBox = document.getElementById("send-error");
    errorBox.classList.add("hidden");
    const data = new FormData(sendForm);
    const file = sendForm.querySelector('input[type="file"]').files[0];
    const recipient = sendForm.querySelector("select").selectedOptions[0];

    showModal("pipeline-modal");
    document.getElementById("pipeline-complete").classList.add("hidden");
    document.getElementById("pipeline-meta").classList.add("hidden");

    const request = fetch("/api/send", { method: "POST", body: data });
    await animatePipeline("#pipeline-steps li");
    const response = await request;
    const payload = await response.json();

    if (!payload.ok) {
      hideModal("pipeline-modal");
      errorBox.textContent = payload.error || "Secure send failed.";
      errorBox.classList.remove("hidden");
      return;
    }

    document.getElementById("pipeline-complete").classList.remove("hidden");
    const meta = document.getElementById("pipeline-meta");
    meta.classList.remove("hidden");
    meta.innerHTML = `
      <div><dt>Recipient</dt><dd>${payload.recipient_id}</dd></div>
      <div><dt>File</dt><dd>${payload.original_filename}</dd></div>
      <div><dt>File size</dt><dd>${formatSize(payload.size_bytes)}</dd></div>
      <div><dt>Encryption</dt><dd>AES-256-GCM</dd></div>
      <div><dt>Key encapsulation</dt><dd>ML-KEM-768</dd></div>
      <div><dt>Identity</dt><dd>Verified (${recipient.text})</dd></div>
      <div><dt>Status</dt><dd>SECURE</dd></div>
    `;
  });
}

async function runDecrypt(fileId, unauthorized = false) {
  showModal("pipeline-modal");
  const result = document.getElementById("decrypt-result");
  if (result) {
    result.classList.add("hidden");
    result.innerHTML = "";
  }
  const kicker = document.getElementById("decrypt-kicker");
  if (kicker) kicker.textContent = unauthorized ? "Unauthorized Access Attempt" : "Decryption Sequence";

  const url = unauthorized ? `/api/files/${fileId}/unauthorized` : `/api/files/${fileId}/decrypt`;
  const request = fetch(url, { method: "POST" });
  if (document.querySelector("#decrypt-steps li")) {
    await animatePipeline("#decrypt-steps li", unauthorized ? 220 : 340);
  }
  const response = await request;
  const payload = await response.json();

  if (!result) return;
  result.classList.remove("hidden");

  if (payload.code === "access_denied") {
    result.innerHTML = `
      <div class="denied">
        <h3>ACCESS DENIED</h3>
        <p>${payload.error}</p>
        <p><strong>Reason:</strong> ${payload.reason || "Recipient identity does not match authorized identity."}</p>
        <p>${payload.detail || "ML-KEM private key unavailable for this identity."}</p>
      </div>`;
    return;
  }

  if (!payload.ok) {
    result.innerHTML = `<div class="banner error">${payload.error || "Decryption failed."}</div>`;
    return;
  }

  result.innerHTML = `
    <p class="complete">✓ FILE RECOVERED</p>
    <dl class="meta">
      <div><dt>Original SHA-256</dt><dd class="hash">${payload.original_sha256}</dd></div>
      <div><dt>Recovered SHA-256</dt><dd class="hash">${payload.recovered_sha256}</dd></div>
      <div><dt>Integrity</dt><dd><span class="pill">${payload.integrity}</span></dd></div>
    </dl>
    <p><a class="btn primary" href="/api/files/download/${payload.download_token}">Download original file</a></p>
  `;
}

document.querySelectorAll(".decrypt-btn").forEach((button) => {
  button.addEventListener("click", () => runDecrypt(button.dataset.id, false));
});

document.querySelectorAll(".unauthorized-btn").forEach((button) => {
  button.addEventListener("click", () => runDecrypt(button.dataset.id, true));
});

const simulateForm = document.getElementById("simulate-form");
if (simulateForm) {
  simulateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const box = document.getElementById("simulate-result");
    box.innerHTML = "<p class='muted'>Running envelope encryption and recovery…</p>";
    const response = await fetch("/api/security/simulate", { method: "POST", body: new FormData(simulateForm) });
    const payload = await response.json();
    if (payload.code === "access_denied") {
      box.innerHTML = `
        <div class="denied">
          <h3>ACCESS DENIED</h3>
          <p>Your identity is not authorized to decrypt this file.</p>
          <p>Reason: Recipient identity does not match authorized identity.</p>
          <p>ML-KEM private key unavailable for this identity.</p>
        </div>`;
      return;
    }
    if (!payload.ok) {
      box.innerHTML = `<div class="banner error">${payload.error}</div>`;
      return;
    }
    box.innerHTML = `
      <dl class="meta">
        <div><dt>Original file</dt><dd>${payload.original_filename}</dd></div>
        <div><dt>Original SHA-256</dt><dd class="hash">${payload.original_sha256}</dd></div>
        <div><dt>Recovered SHA-256</dt><dd class="hash">${payload.recovered_sha256}</dd></div>
        <div><dt>Encrypted SHA-256</dt><dd class="hash">${payload.ciphertext_sha256}</dd></div>
        <div><dt>Integrity</dt><dd><span class="pill">${payload.integrity}</span></dd></div>
      </dl>`;
  });
}

document.getElementById("pipeline-modal")?.addEventListener("click", (event) => {
  if (event.target.id === "pipeline-modal") hideModal("pipeline-modal");
});
