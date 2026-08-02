const magic = new TextEncoder().encode("CLEAVER1\n");
const keyPrefix = "clv1:";
const headerLenBytes = 4;
const themeKey = "cleaver-theme";

const $ = (selector) => document.querySelector(selector);

let decryptLockSupported = false;

initTheme();

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});
document.querySelectorAll("[data-tab-target]").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tabTarget));
});

setupDropzone("encryptAsset", "encryptDropzone", "encryptFileMeta");
setupDropzone("decryptAsset", "decryptDropzone", "decryptFileMeta");

$("#themeToggle").addEventListener("click", toggleTheme);
$("#encryptAsset").addEventListener("change", syncEncryptSubmit);
$("#encryptPin").addEventListener("input", syncEncryptSubmit);
$("#decryptAsset").addEventListener("change", inspectLockFile);
$("#decryptPin").addEventListener("input", syncDecryptSubmit);
$("#decryptShards").addEventListener("change", syncDecryptSubmit);
$("#clearCredentials").addEventListener("click", clearCredentials);

syncEncryptSubmit();
syncDecryptSubmit();
activateTab(tabFromHash());
window.addEventListener("hashchange", () => activateTab(tabFromHash()));

$("#encryptForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#encryptStatus");
  const downloads = $("#encryptDownloads");
  setStatus(status, "Encrypting...");

  try {
    const file = form.asset.files[0];
    if (!file) throw new Error("Choose a file first.");
    const plain = new Uint8Array(await file.arrayBuffer());
    const assets = await encryptWithPinAssets(plain, file.name, form.pin.value);
    renderDownloads(downloads, assets);
    setStatus(status, "Encrypted. Download the lock file, shards, and recovery instructions.");
  } catch (error) {
    setStatus(status, error.message, true);
  }
});

$("#decryptForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#decryptStatus");
  const downloads = $("#decryptDownloads");
  setStatus(status, "Decrypting...");

  try {
    const file = form.asset.files[0];
    if (!file) throw new Error("Choose a lock file first.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    if (decoded.header.kdf !== "pin-sha256") throw new Error("This lock file was not created with Cleaver's PIN workflow.");

    const pin = form.pin.value;
    validatePin(pin);
    const keyBytes = await keyFromShardFiles(form.shards.files, pin);
    const plain = await unlockDecoded(decoded, keyBytes);
    const name = decoded.header.original_name || stripLockExtension(file.name);
    renderDownloads(downloads, [asset(name, plain, "Decrypted file", "Plain file recovered from the lock file.")]);
    setStatus(status, "Decrypted. Download is ready.");
  } catch (error) {
    setStatus(status, error.message, true);
  }
});

function initTheme() {
  const saved = localStorage.getItem(themeKey);
  const preferred = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  applyTheme(saved || preferred);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem(themeKey, next);
  applyTheme(next);
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("#themeToggle").textContent = theme === "dark" ? "Light" : "Dark";
}

function activateTab(name) {
  if (!["intro", "encrypt", "decrypt"].includes(name)) name = "intro";
  document.querySelectorAll(".tab,.screen").forEach((el) => el.classList.remove("active"));
  document.querySelector(`.tab[data-tab="${name}"]`)?.classList.add("active");
  $("#" + name).classList.add("active");
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
}

function tabFromHash() {
  return location.hash.replace(/^#/, "") || "intro";
}

function setupDropzone(inputId, zoneId, metaId) {
  const input = $("#" + inputId);
  const zone = $("#" + zoneId);
  const meta = $("#" + metaId);

  ["dragenter", "dragover"].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.remove("dragover");
    });
  });
  zone.addEventListener("drop", (event) => {
    if (!event.dataTransfer.files.length) return;
    input.files = event.dataTransfer.files;
    input.dispatchEvent(new Event("change"));
  });
  input.addEventListener("change", () => {
    const file = input.files[0];
    meta.textContent = file
      ? `${file.name} - ${formatBytes(file.size)}`
      : inputId === "decryptAsset" ? "No lock file selected." : "No file selected.";
  });
}

function syncEncryptSubmit() {
  const form = $("#encryptForm");
  $("#encryptSubmit").disabled = !(form.asset.files[0] && form.pin.value);
}

function syncDecryptSubmit() {
  const form = $("#decryptForm");
  $("#decryptSubmit").disabled = !(decryptLockSupported && form.asset.files[0] && form.pin.value && form.shards.files.length);
}

async function inspectLockFile() {
  const form = $("#decryptForm");
  const file = form.asset.files[0];
  decryptLockSupported = false;
  syncDecryptSubmit();
  if (!file) {
    $("#decryptCredentialSummary").textContent = "Select a lock file to read its encryption metadata.";
    return;
  }

  try {
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    $("#decryptCredentialSummary").textContent = credentialSummary(decoded.header, file.name);
    decryptLockSupported = decoded.header.kdf === "pin-sha256";
    syncDecryptSubmit();
    setStatus(
      $("#decryptStatus"),
      decryptLockSupported ? "Lock metadata read. Enter the PIN and shard files." : "This lock uses an unsupported unlock method.",
      !decryptLockSupported,
    );
  } catch (error) {
    decryptLockSupported = false;
    $("#decryptSubmit").disabled = true;
    setStatus($("#decryptStatus"), error.message, true);
  }
}

function credentialSummary(header, fallbackName) {
  const name = header.original_name || stripLockExtension(fallbackName);
  if (header.kdf === "pin-sha256") return `${name} requires its PIN and shard files.`;
  return `${name} was made with an older unlock method.`;
}

function clearCredentials() {
  const form = $("#decryptForm");
  form.pin.value = "";
  form.shards.value = "";
  syncDecryptSubmit();
  setStatus($("#decryptStatus"), "Credentials cleared.");
}

async function encryptWithPinAssets(plain, name, pin) {
  validatePin(pin);
  const shards = createKeyShards();
  const keyBytes = await combineShards(shards, pin);
  const locked = await lockBytes(plain, { kind: "raw", keyBytes, pin: true }, name);
  const assets = [
    asset(outputName(name, ".lock"), locked, "Encrypted lock file", "Decrypt this with the PIN and shard files."),
  ];
  for (let digit = 0; digit <= 9; digit++) {
    assets.push(asset(String(digit), textBytes(keyPrefix + base64URL(shards[String(digit)]) + "\n"), `Shard ${digit}`, "One shard file used with your PIN."));
  }
  assets.push(asset(outputName(name, "-recovery.txt"), textBytes(recoveryText(name)), "Recovery instructions", "Keep this with your shard storage plan."));
  return assets;
}

async function lockBytes(plain, spec, originalName) {
  const nonce = randomBytes(12);
  if (spec.kind !== "raw" || !spec.pin) throw new Error("Cleaver encrypts files only with random key material and a PIN requirement.");
  const header = {
    version: 1,
    cipher: "AES-256-GCM",
    kdf: "pin-sha256",
    nonce: base64URL(nonce),
    original_name: baseName(originalName),
  };

  const prefix = encodePrefix(header);
  const key = await importAESKey(spec.keyBytes);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: prefix },
    key,
    plain,
  ));
  return concatBytes(prefix, ciphertext);
}

function decodeLock(data) {
  if (data.length < magic.length + headerLenBytes) throw new Error("Not a Cleaver lock file.");
  for (let i = 0; i < magic.length; i++) {
    if (data[i] !== magic[i]) throw new Error("Not a Cleaver lock file.");
  }

  const view = new DataView(data.buffer, data.byteOffset + magic.length, headerLenBytes);
  const headerLength = view.getUint32(0, false);
  const headerStart = magic.length + headerLenBytes;
  const headerEnd = headerStart + headerLength;
  if (headerEnd > data.length) throw new Error("Truncated lock header.");

  const header = JSON.parse(new TextDecoder().decode(data.slice(headerStart, headerEnd)));
  if (header.version !== 1) throw new Error(`Unsupported lock version ${header.version}.`);
  if (header.cipher !== "AES-256-GCM") throw new Error(`Unsupported cipher ${header.cipher}.`);

  return {
    header,
    prefix: data.slice(0, headerEnd),
    ciphertext: data.slice(headerEnd),
  };
}

async function unlockDecoded(decoded, keyBytes) {
  if (decoded.header.kdf !== "pin-sha256") throw new Error("This lock file was not created with Cleaver's PIN workflow.");
  const key = await importAESKey(keyBytes);
  const nonce = base64URLDecode(decoded.header.nonce);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: decoded.prefix },
      key,
      decoded.ciphertext,
    ));
  } catch {
    throw new Error("Decrypt failed: wrong key or corrupted lock file.");
  }
}

async function importAESKey(keyBytes) {
  if (keyBytes.length !== 32) throw new Error(`AES key must be 32 bytes, got ${keyBytes.length}.`);
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function encodePrefix(header) {
  const headerBytes = textBytes(JSON.stringify(header));
  const out = new Uint8Array(magic.length + headerLenBytes + headerBytes.length);
  out.set(magic, 0);
  new DataView(out.buffer).setUint32(magic.length, headerBytes.length, false);
  out.set(headerBytes, magic.length + headerLenBytes);
  return out;
}

function parseRawKey(text) {
  const trimmed = text.trim();
  if (!trimmed.startsWith(keyPrefix)) throw new Error("Key must be a clv1 raw key token.");
  const key = base64URLDecode(trimmed.slice(keyPrefix.length));
  if (key.length !== 32) throw new Error(`clv1 key must decode to 32 bytes, got ${key.length}.`);
  return key;
}

function createKeyShards() {
  const shards = {};
  for (let digit = 0; digit <= 9; digit++) shards[String(digit)] = randomBytes(32);
  return shards;
}

async function combineShards(shards, pin) {
  const parts = [];
  for (const digit of pin) {
    const shard = shards[digit];
    if (!shard) throw new Error(`Missing key shard ${digit}.`);
    parts.push(shard);
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(...parts)));
}

async function keyFromShardFiles(files, pin) {
  if (!files || files.length === 0) throw new Error("Shard files are required.");
  const shards = {};
  for (const file of files) {
    const name = baseName(file.name);
    if (!/^[0-9]$/.test(name)) continue;
    shards[name] = parseRawKey(await file.text());
  }
  for (let digit = 0; digit <= 9; digit++) {
    if (!shards[String(digit)]) throw new Error(`Missing key shard ${digit}.`);
  }
  return combineShards(shards, pin);
}

function validatePin(pin) {
  if (!pin) throw new Error("PIN must not be empty.");
  if (!/^[0-9]+$/.test(pin)) throw new Error("PIN must contain only digits 0-9.");
}

function renderDownloads(root, assets) {
  root.innerHTML = "";
  for (const item of assets) addDownload(root, item);
}

function addDownload(root, item) {
  const row = document.createElement("div");
  row.className = "download";
  const label = document.createElement("div");
  const strong = document.createElement("strong");
  strong.textContent = item.label;
  const code = document.createElement("code");
  code.textContent = item.name;
  const purpose = document.createElement("small");
  purpose.textContent = item.purpose || "Download generated file.";
  label.append(strong, code, purpose);
  const link = document.createElement("a");
  link.className = "secondary";
  link.href = URL.createObjectURL(new Blob([item.data], { type: "application/octet-stream" }));
  link.download = item.name;
  link.textContent = "Download";
  row.append(label, link);
  root.append(row);
}

function asset(name, data, label, purpose) {
  return { name: baseName(name), data, label, purpose };
}

function recoveryText(name) {
  return `Cleaver recovery note\n\nFile: ${baseName(name)}\nProtection: random browser-generated key plus PIN-derived shard unlock\n\nCleaver cannot recover a lost PIN or shard set. Store the lock file and required unlock material separately.\n`;
}

function setStatus(el, text, error = false) {
  el.className = error ? "status err" : "status";
  el.textContent = text;
}

function outputName(name, ext) {
  const clean = baseName(name);
  const dot = clean.lastIndexOf(".");
  return (dot > 0 ? clean.slice(0, dot) : clean) + ext;
}

function stripLockExtension(name) {
  const clean = baseName(name);
  return clean.endsWith(".lock") ? clean.slice(0, -5) : clean;
}

function baseName(name) {
  return String(name).split(/[\\/]/).pop() || "asset";
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function textBytes(text) {
  return new TextEncoder().encode(text);
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64URL(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64URLDecode(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
