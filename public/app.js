const magic = new TextEncoder().encode("CLEAVER1\n");
const keyPrefix = "clv1:";
const bundleMagic = "CLEAVER-BUNDLE1\n";
const headerLenBytes = 4;

const $ = (selector) => document.querySelector(selector);

let decryptLockSupported = false;
let editLockSupported = false;
let editorState = null;

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});
document.querySelectorAll("[data-tab-target]").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tabTarget));
});

setupDropzone("encryptAsset", "encryptDropzone", "encryptFileMeta");
setupDropzone("decryptAsset", "decryptDropzone", "decryptFileMeta", "decryptShards");
setupDropzone("editAsset", "editDropzone", "editFileMeta", "editShards");

$("#encryptAsset").addEventListener("change", syncEncryptSubmit);
$("#encryptPin").addEventListener("input", syncEncryptSubmit);
$("#decryptAsset").addEventListener("change", inspectLockFile);
$("#decryptPin").addEventListener("input", syncDecryptSubmit);
$("#decryptShards").addEventListener("change", syncDecryptSubmit);
$("#clearCredentials").addEventListener("click", clearCredentials);
$("#editAsset").addEventListener("change", inspectEditLockFile);
$("#editPin").addEventListener("input", syncEditSubmit);
$("#editShards").addEventListener("change", syncEditSubmit);
$("#closeEditor").addEventListener("click", closeEditor);
$("#exportLock").addEventListener("click", exportEditedLock);
$("#addSheetRow").addEventListener("click", addSheetRow);
$("#addSheetColumn").addEventListener("click", addSheetColumn);

syncEncryptSubmit();
syncDecryptSubmit();
syncEditSubmit();
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
    requireCSVName(file.name);
    const plain = new Uint8Array(await file.arrayBuffer());
    const assets = await encryptWithPinAssets(plain, file.name, form.pin.value);
    renderDownloads(downloads, assets);
    setStatus(status, "Encrypted. Download the lock file and its key bundle.");
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
    const keyBytes = await keyFromShardFiles(form.shards.files, pin, decoded.header);
    const plain = await unlockDecoded(decoded, keyBytes);
    const name = decoded.header.original_name || stripLockExtension(file.name);
    renderDownloads(downloads, [asset(name, plain, "Decrypted file", "Plain file recovered from the lock file.")]);
    setStatus(status, "Decrypted. Download is ready.");
  } catch (error) {
    setStatus(status, error.message, true);
  }
});

$("#editForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setStatus($("#editStatus"), "Checking credentials and opening file...");
  try {
    const file = form.asset.files[0];
    if (!file) throw new Error("Choose a lock file first.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    validatePin(form.pin.value);
    const keyBytes = await keyFromShardFiles(form.shards.files, form.pin.value, decoded.header);
    const plain = await unlockDecoded(decoded, keyBytes);
    const originalName = decoded.header.original_name || stripLockExtension(file.name);
    requireCSVName(originalName);
    const text = decodeText(plain);
    const rows = normalizeCSVRows(parseCSV(text));
    editorState = {
      keyBytes,
      shardIds: decoded.header.shard_ids,
      originalName,
      rows,
    };
    form.pin.value = "";
    form.shards.value = "";
    renderSpreadsheet();
    $("#textWorkspace").hidden = false;
    $("#editForm").hidden = true;
    $("#editorTitle").textContent = originalName;
    updateSpreadsheetMeta();
    setStatus($("#editStatus"), "");
    $("#textWorkspace").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus($("#editStatus"), error.message, true);
  }
});

function activateTab(name) {
  if (!["intro", "encrypt", "decrypt", "edit"].includes(name)) name = "intro";
  document.querySelectorAll(".tab,.screen").forEach((el) => el.classList.remove("active"));
  document.querySelector(`.tab[data-tab="${name}"]`)?.classList.add("active");
  $("#" + name).classList.add("active");
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
}

function tabFromHash() {
  return location.hash.replace(/^#/, "") || "intro";
}

function setupDropzone(inputId, zoneId, metaId, bundleInputId = "") {
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
    let selectedBundle = null;
    if (bundleInputId) {
      const selectedFiles = Array.from(input.files);
      const lockFile = selectedFiles.find((file) => file.name.toLowerCase().endsWith(".lock"));
      selectedBundle = selectedFiles.find((file) => /\.(bundle|key)$/i.test(file.name));
      if (lockFile) setInputFiles(input, [lockFile]);
      if (selectedBundle) {
        const bundleInput = $("#" + bundleInputId);
        setInputFiles(bundleInput, [selectedBundle]);
        bundleInput.dispatchEvent(new Event("change"));
      }
    }
    const file = input.files[0];
    meta.textContent = file
      ? `${file.name} - ${formatBytes(file.size)}${selectedBundle ? ` + ${selectedBundle.name}` : ""}`
      : ["decryptAsset", "editAsset"].includes(inputId) ? "No lock file selected." : "No file selected.";
  });
}

function setInputFiles(input, files) {
  const transfer = new DataTransfer();
  files.forEach((file) => transfer.items.add(file));
  input.files = transfer.files;
}

function syncEncryptSubmit() {
  const form = $("#encryptForm");
  $("#encryptSubmit").disabled = !(form.asset.files[0] && form.pin.value);
}

function syncDecryptSubmit() {
  const form = $("#decryptForm");
  $("#decryptSubmit").disabled = !(decryptLockSupported && form.asset.files[0] && form.pin.value && form.shards.files.length);
}

function syncEditSubmit() {
  const form = $("#editForm");
  $("#editUnlockSubmit").disabled = !(editLockSupported && form.asset.files[0] && form.pin.value && form.shards.files.length);
}

async function inspectEditLockFile() {
  const file = $("#editForm").asset.files[0];
  editLockSupported = false;
  if (!file) return syncEditSubmit();
  try {
    if (!file.name.toLowerCase().endsWith(".lock")) throw new Error("Choose a Cleaver .lock file.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    requireCSVName(decoded.header.original_name || stripLockExtension(file.name));
    editLockSupported = decoded.header.kdf === "pin-sha256";
    setStatus($("#editStatus"), editLockSupported ? `${decoded.header.original_name || stripLockExtension(file.name)} is ready for spreadsheet editing.` : "This lock uses an unsupported unlock method.", !editLockSupported);
  } catch (error) {
    setStatus($("#editStatus"), error.message, true);
  }
  syncEditSubmit();
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
      decryptLockSupported ? "Lock metadata read. Enter the PIN and select its key bundle." : "This lock uses an unsupported unlock method.",
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
  if (header.kdf === "pin-sha256") return `${name} requires its PIN and ${header.shard_ids ? "key bundle" : "legacy shard files"}.`;
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
  requireWebCrypto();
  validatePin(pin);
  const shards = createKeyShards();
  const shardIds = Array.from({ length: 10 }, () => base64URL(randomBytes(12)));
  const keyBytes = await combineShards(shards, pin);
  const locked = await lockBytes(plain, { kind: "raw", keyBytes, pin: true, shardIds }, name);
  const bundle = encodeKeyBundle(shards, shardIds);
  return [
    asset(outputName(name, ".lock"), locked, "Encrypted lock file", "The encrypted file. Editing it only creates a replacement lock file."),
    asset(outputName(name, ".bundle"), bundle, "Key bundle", "Keep this bundle and the PIN; it contains the randomly ordered key material."),
  ];
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
  if (spec.shardIds) header.shard_ids = validateShardIds(spec.shardIds);

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
  requireWebCrypto();
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
  requireWebCrypto();
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
  requireWebCrypto();
  const parts = [];
  for (const digit of pin) {
    const shard = shards[digit];
    if (!shard) throw new Error(`Missing key shard ${digit}.`);
    parts.push(shard);
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(...parts)));
}

function requireWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Encryption is unavailable on this page. Open Cleaver at http://localhost:5544 on this computer, or serve it over HTTPS.");
  }
}

async function keyFromShardFiles(files, pin, header = {}) {
  if (!files || files.length === 0) throw new Error(header.shard_ids ? "A key bundle is required." : "Shard files are required.");
  if (header.shard_ids) {
    if (files.length !== 1) throw new Error("Select the single key bundle created with this lock file.");
    return combineShards(await decodeKeyBundle(files[0], header.shard_ids), pin);
  }
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

function encodeKeyBundle(shards, shardIds) {
  const entries = shardIds.map((id, digit) => ({ id, value: base64URL(shards[String(digit)]) }));
  crypto.getRandomValues(new Uint32Array(entries.length)).forEach((random, index) => {
    const other = index + (random % (entries.length - index));
    [entries[index], entries[other]] = [entries[other], entries[index]];
  });
  return textBytes(bundleMagic + JSON.stringify({ version: 1, entries }));
}

async function decodeKeyBundle(file, shardIds) {
  const text = await file.text();
  if (!text.startsWith(bundleMagic)) throw new Error("This is not a Cleaver key bundle.");
  let bundle;
  try {
    bundle = JSON.parse(text.slice(bundleMagic.length));
  } catch {
    throw new Error("The key bundle is corrupted.");
  }
  if (bundle.version !== 1 || !Array.isArray(bundle.entries)) throw new Error("Unsupported key bundle format.");
  const byId = new Map();
  for (const entry of bundle.entries) {
    if (!entry || typeof entry.id !== "string" || typeof entry.value !== "string" || byId.has(entry.id)) {
      throw new Error("The key bundle is corrupted.");
    }
    byId.set(entry.id, base64URLDecode(entry.value));
  }
  const shards = {};
  validateShardIds(shardIds).forEach((id, digit) => {
    const value = byId.get(id);
    if (!value || value.length !== 32) throw new Error("This key bundle does not belong to the selected lock file.");
    shards[String(digit)] = value;
  });
  return shards;
}

function validateShardIds(shardIds) {
  if (!Array.isArray(shardIds) || shardIds.length !== 10 || new Set(shardIds).size !== 10 || shardIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9_-]{16}$/.test(id))) {
    throw new Error("The lock file has invalid key bundle metadata.");
  }
  return shardIds;
}

function validatePin(pin) {
  if (!pin) throw new Error("PIN must not be empty.");
  if (!/^[0-9]+$/.test(pin)) throw new Error("PIN must contain only digits 0-9.");
}

function decodeText(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("The unlocked file is not valid UTF-8 text.");
  }
}

function requireCSVName(name) {
  if (!/\.csv$/i.test(baseName(name))) {
    throw new Error("This workflow requires a locked CSV file.");
  }
}

function closeEditor() {
  editorState = null;
  $("#spreadsheetGrid").replaceChildren();
  $("#textWorkspace").hidden = true;
  $("#editForm").hidden = false;
  $("#editForm").reset();
  $("#editFileMeta").textContent = "No lock file selected.";
  $("#editDownloads").innerHTML = "";
  editLockSupported = false;
  syncEditSubmit();
}

async function exportEditedLock() {
  if (!editorState) return;
  setStatus($("#exportStatus"), "Encrypting edited CSV...");
  try {
    const text = serializeCSV(editorState.rows);
    const plain = textBytes(text);
    const locked = await lockBytes(plain, { kind: "raw", keyBytes: editorState.keyBytes, pin: true, shardIds: editorState.shardIds }, editorState.originalName);
    const name = outputName(editorState.originalName, ".lock");
    renderDownloads($("#editDownloads"), [asset(name, locked, "Edited CSV lock file", "Protected by the same PIN and key bundle.")]);
    setStatus($("#exportStatus"), "New lock file ready. Your original lock file was not changed.");
  } catch (error) {
    setStatus($("#exportStatus"), error.message, true);
  }
}

function renderSpreadsheet(focusRow = 0, focusCol = 0) {
  if (!editorState) return;
  const grid = $("#spreadsheetGrid");
  grid.replaceChildren();
  const rows = editorState.rows;
  const columnCount = rows[0]?.length || 1;

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(document.createElement("th"));
  for (let col = 0; col < columnCount; col++) {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = spreadsheetColumnName(col);
    headRow.append(th);
  }
  thead.append(headRow);

  const tbody = document.createElement("tbody");
  rows.forEach((row, rowIndex) => {
    const tr = document.createElement("tr");
    const rowHead = document.createElement("th");
    rowHead.scope = "row";
    rowHead.textContent = String(rowIndex + 1);
    tr.append(rowHead);
    row.forEach((cell, colIndex) => {
      const td = document.createElement("td");
      const input = document.createElement("input");
      input.className = "sheet-cell";
      input.value = cell;
      input.dataset.row = String(rowIndex);
      input.dataset.col = String(colIndex);
      input.setAttribute("aria-label", `${spreadsheetColumnName(colIndex)}${rowIndex + 1}`);
      input.addEventListener("input", updateSpreadsheetCell);
      input.addEventListener("keydown", handleSpreadsheetKeydown);
      td.append(input);
      tr.append(td);
    });
    tbody.append(tr);
  });

  grid.append(thead, tbody);
  updateSpreadsheetMeta();
  focusSpreadsheetCell(Math.min(focusRow, rows.length - 1), Math.min(focusCol, columnCount - 1));
}

function updateSpreadsheetCell(event) {
  const row = Number(event.currentTarget.dataset.row);
  const col = Number(event.currentTarget.dataset.col);
  editorState.rows[row][col] = event.currentTarget.value;
}

function handleSpreadsheetKeydown(event) {
  const input = event.currentTarget;
  const row = Number(input.dataset.row);
  const col = Number(input.dataset.col);
  let nextRow = row;
  let nextCol = col;

  if (event.key === "Enter") {
    event.preventDefault();
    nextRow = event.shiftKey ? row - 1 : row + 1;
  } else if (event.key === "Tab") {
    event.preventDefault();
    nextCol = event.shiftKey ? col - 1 : col + 1;
  } else if (event.key === "ArrowUp" && input.selectionStart === 0 && input.selectionEnd === 0) {
    event.preventDefault();
    nextRow = row - 1;
  } else if (event.key === "ArrowDown" && input.selectionStart === input.value.length && input.selectionEnd === input.value.length) {
    event.preventDefault();
    nextRow = row + 1;
  }

  if (nextRow !== row || nextCol !== col) {
    focusSpreadsheetCell(nextRow, nextCol);
  }
}

function focusSpreadsheetCell(row, col) {
  if (!editorState) return;
  if (row < 0 || col < 0 || row >= editorState.rows.length || col >= editorState.rows[0].length) return;
  const cell = $(`#spreadsheetGrid .sheet-cell[data-row="${row}"][data-col="${col}"]`);
  if (!cell) return;
  cell.focus();
  cell.select();
}

function addSheetRow() {
  if (!editorState) return;
  const columnCount = editorState.rows[0]?.length || 1;
  editorState.rows.push(Array.from({ length: columnCount }, () => ""));
  renderSpreadsheet(editorState.rows.length - 1, 0);
  setStatus($("#exportStatus"), "Row added. It will be included when you export.");
}

function addSheetColumn() {
  if (!editorState) return;
  editorState.rows.forEach((row) => row.push(""));
  renderSpreadsheet(0, editorState.rows[0].length - 1);
  setStatus($("#exportStatus"), "Column added. It will be included when you export.");
}

function updateSpreadsheetMeta() {
  if (!editorState) return;
  const rows = editorState.rows.length;
  const cols = editorState.rows[0]?.length || 0;
  $("#editorMeta").textContent = `${rows} ${rows === 1 ? "row" : "rows"} x ${cols} ${cols === 1 ? "column" : "columns"}`;
}

function spreadsheetColumnName(index) {
  let name = "";
  let value = index + 1;
  while (value > 0) {
    const remainder = (value - 1) % 26;
    name = String.fromCharCode(65 + remainder) + name;
    value = Math.floor((value - 1) / 26);
  }
  return name;
}

function parseCSV(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  let index = text.startsWith("\uFEFF") ? 1 : 0;

  for (; index < text.length; index++) {
    const char = text[index];
    if (quoted) {
      if (char === "\"") {
        if (text[index + 1] === "\"") {
          cell += "\"";
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += char;
      }
      continue;
    }

    if (char === "\"") {
      if (cell.length === 0) {
        quoted = true;
      } else {
        throw new Error("Invalid CSV: quotes must begin a cell or be escaped.");
      }
    } else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n" || char === "\r") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      if (char === "\r" && text[index + 1] === "\n") index += 1;
    } else {
      cell += char;
    }
  }

  if (quoted) throw new Error("Invalid CSV: quoted cell is not closed.");
  if (cell.length || row.length || rows.length === 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

function normalizeCSVRows(rows) {
  const columnCount = Math.max(1, ...rows.map((row) => row.length));
  const normalized = rows.map((row) => {
    const next = row.slice();
    while (next.length < columnCount) next.push("");
    return next;
  });
  return normalized.length ? normalized : [[""]];
}

function serializeCSV(rows) {
  return rows.map((row) => row.map(escapeCSVCell).join(",")).join("\n") + "\n";
}

function escapeCSVCell(value) {
  const text = String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, "\"\"")}"`;
  return text;
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
