const $ = (selector) => document.querySelector(selector);
const magic = new TextEncoder().encode("CLEAVER1\n");
const bundleMagic = "CLEAVER-BUNDLE1\n";
let bundleBytes = null;
let lockRecord = null;
let unlocked = null;
let cameraStream = null;

$("#startScanner").addEventListener("click", startScanner);
$("#useManualBundle").addEventListener("click", useManualBundle);
$("#accessUnlockForm").addEventListener("submit", unlock);
$("#downloadUnlocked").addEventListener("click", downloadUnlocked);

async function startScanner() {
  setStatus($("#scanStatus"), "Opening camera...");
  try {
    if (!("BarcodeDetector" in window)) throw new Error("QR scanning is not supported by this browser. Use the bundle file below instead.");
    const formats = await BarcodeDetector.getSupportedFormats();
    if (!formats.includes("qr_code")) throw new Error("This browser cannot scan QR codes. Use the bundle file below instead.");
    cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
    const video = $("#scannerVideo"); video.srcObject = cameraStream; video.hidden = false; await video.play();
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    setStatus($("#scanStatus"), "Point the camera at your bundle QR code.");
    const scan = async () => {
      if (!cameraStream) return;
      try {
        const codes = await detector.detect(video);
        if (codes[0]?.rawValue) { acceptBundlePayload(codes[0].rawValue); return; }
      } catch {}
      requestAnimationFrame(scan);
    };
    requestAnimationFrame(scan);
  } catch (error) { stopCamera(); setStatus($("#scanStatus"), error.message, true); }
}

async function useManualBundle() {
  try {
    const file = $("#bundleFile").files[0];
    if (file) acceptBundleBytes(new Uint8Array(await file.arrayBuffer()));
    else acceptBundlePayload($("#bundleText").value.trim());
  } catch (error) { setStatus($("#scanStatus"), error.message, true); }
}

function acceptBundlePayload(payload) {
  if (!payload.startsWith("cleaver-bundle:")) throw new Error("That QR code is not a Cleaver bundle.");
  acceptBundleBytes(base64URLDecode(payload.slice("cleaver-bundle:".length)));
}

function acceptBundleBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  if (!text.startsWith(bundleMagic)) throw new Error("That is not a Cleaver bundle.");
  JSON.parse(text.slice(bundleMagic.length));
  bundleBytes = bytes; stopCamera(); $("#scanStep").hidden = true; $("#pinStep").hidden = false; $("#accessPin").focus();
}

function stopCamera() {
  cameraStream?.getTracks().forEach((track) => track.stop()); cameraStream = null;
  const video = $("#scannerVideo"); video.pause(); video.srcObject = null; video.hidden = true;
}

async function unlock(event) {
  event.preventDefault(); setStatus($("#accessStatus"), "Unlocking in this browser...");
  try {
    const pin = $("#accessPin").value;
    if (!/^\d+$/.test(pin)) throw new Error("Enter the numeric PIN.");
    if (!lockRecord) {
      const token = $(".access-main").dataset.lockToken;
      const response = await fetch(`/api/locks/${token}`, { cache: "no-store" });
      if (!response.ok) throw new Error("This lock is unavailable.");
      lockRecord = await response.json();
    }
    const decoded = decodeLock(base64Bytes(lockRecord.data));
    const shards = decodeBundle(bundleBytes, decoded.header.shard_ids);
    const parts = [...pin].map((digit) => shards[digit]);
    const keyBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(...parts)));
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    try {
      unlocked = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64URLDecode(decoded.header.nonce), additionalData: decoded.prefix }, key, decoded.ciphertext));
    } catch { throw new Error("Unlock failed. Check the bundle and PIN."); }
    renderCSV(new TextDecoder("utf-8", { fatal: true }).decode(unlocked));
    $("#pinStep").hidden = true; $("#accessResults").hidden = false; $("#accessPin").value = "";
  } catch (error) { setStatus($("#accessStatus"), error.message, true); }
}

function decodeLock(data) {
  if (data.length < 12 || !magic.every((byte, i) => data[i] === byte)) throw new Error("Invalid lock file.");
  const length = new DataView(data.buffer, data.byteOffset + magic.length, 4).getUint32(0, false);
  const end = magic.length + 4 + length;
  const header = JSON.parse(new TextDecoder().decode(data.slice(magic.length + 4, end)));
  return { header, prefix: data.slice(0, end), ciphertext: data.slice(end) };
}

function decodeBundle(data, ids) {
  const text = new TextDecoder().decode(data);
  const parsed = JSON.parse(text.slice(bundleMagic.length));
  const byID = new Map(parsed.entries.map((entry) => [entry.id, base64URLDecode(entry.value)]));
  const shards = {};
  ids.forEach((id, digit) => { const value = byID.get(id); if (!value || value.length !== 32) throw new Error("This bundle does not belong to this lock."); shards[digit] = value; });
  return shards;
}

function renderCSV(text) {
  const rows = parseCSV(text); const grid = $("#accessGrid"); grid.replaceChildren();
  rows.forEach((row, index) => { const tr = document.createElement("tr"); row.forEach((cell) => { const el = document.createElement(index === 0 ? "th" : "td"); el.textContent = cell; tr.append(el); }); grid.append(tr); });
}

function parseCSV(text) {
  const rows = []; let row = [], cell = "", quoted = false;
  for (let i = text.startsWith("\uFEFF") ? 1 : 0; i < text.length; i++) { const char = text[i];
    if (quoted) { if (char === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (char === '"') quoted = false; else cell += char; }
    else if (char === '"') quoted = true; else if (char === ',') { row.push(cell); cell = ""; } else if (char === '\n' || char === '\r') { row.push(cell); rows.push(row); row = []; cell = ""; if (char === '\r' && text[i + 1] === '\n') i++; } else cell += char;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); } return rows;
}

function downloadUnlocked() { if (!unlocked) return; const url = URL.createObjectURL(new Blob([unlocked], { type: "text/csv" })); const a = document.createElement("a"); a.href = url; a.download = lockRecord.filename.replace(/\.lock$/i, ".csv"); a.click(); URL.revokeObjectURL(url); }
function base64Bytes(value) { const raw = atob(value); return Uint8Array.from(raw, (char) => char.charCodeAt(0)); }
function base64URLDecode(value) { let text = value.replace(/-/g, "+").replace(/_/g, "/"); text += "=".repeat((4 - text.length % 4) % 4); return base64Bytes(text); }
function concatBytes(...parts) { const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; parts.forEach((part) => { out.set(part, offset); offset += part.length; }); return out; }
function setStatus(el, text, error = false) { el.className = error ? "status err" : "status"; el.textContent = text.trim(); }
