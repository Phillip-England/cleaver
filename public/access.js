const $ = (selector) => document.querySelector(selector);
const magic = new TextEncoder().encode("CLEAVER1\n");
const bundleMagic = "CLEAVER-BUNDLE1\n";
let bundleBytes = null;
let lockRecord = null;
let unlocked = null;

$("#qrCamera").addEventListener("change", scanCameraImage);
$("#useManualBundle").addEventListener("click", useManualBundle);
$("#accessUnlockForm").addEventListener("submit", unlock);
$("#downloadUnlocked").addEventListener("click", downloadUnlocked);

async function scanCameraImage(event) {
  const file = event.currentTarget.files[0];
  if (!file) return;
  setStatus($("#scanStatus"), "Reading QR code...");
  try {
    const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const result = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    if (!result?.data) throw new Error("No QR code was found. Retake the photo with the full code in focus.");
    acceptBundlePayload(result.data);
  } catch (error) {
    setStatus($("#scanStatus"), error.message, true);
  } finally {
    event.currentTarget.value = "";
  }
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
  bundleBytes = bytes; $("#scanStep").hidden = true; $("#pinStep").hidden = false; $("#accessPin").focus();
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
