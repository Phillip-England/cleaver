const magic = new TextEncoder().encode("CLEAVER1\n");
const keyPrefix = "clv1:";
const bundleMagic = "CLEAVER-BUNDLE1\n";
const headerLenBytes = 4;

const $ = (selector) => document.querySelector(selector);

let decryptLockSupported = false;
let editLockSupported = false;
let renderLockSupported = false;
let alphabetizeLockSupported = false;
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
setupDropzone("renderAsset", "renderDropzone", "renderFileMeta", "renderShards");
setupDropzone("alphabetizeAsset", "alphabetizeDropzone", "alphabetizeFileMeta", "alphabetizeShards");

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
$("#addEditorPage").addEventListener("click", addEditorPage);
$("#editorPageTitle").addEventListener("input", syncEditorPageTitle);
$("#renderAsset").addEventListener("change", inspectRenderLockFile);
$("#renderPin").addEventListener("input", syncRenderSubmit);
$("#renderShards").addEventListener("change", syncRenderSubmit);
$("#alphabetizeAsset").addEventListener("change", inspectAlphabetizeLockFile);
$("#alphabetizePin").addEventListener("input", syncAlphabetizeSubmit);
$("#alphabetizeShards").addEventListener("change", syncAlphabetizeSubmit);

syncEncryptSubmit();
syncDecryptSubmit();
syncEditSubmit();
syncRenderSubmit();
syncAlphabetizeSubmit();
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
    const text = decodeText(plain);
    const paged = /\.(md|markdown)$/i.test(baseName(originalName));
    const pages = paged ? parseMarkdownPages(text) : [{ title: originalName, markdown: text }];
    editorState = {
      keyBytes,
      shardIds: decoded.header.shard_ids,
      originalName,
      paged,
      pages,
      activePageIndex: 0,
    };
    form.pin.value = "";
    form.shards.value = "";
    renderEditorPages();
    $("#textWorkspace").hidden = false;
    $("#editForm").hidden = true;
    $("#editorTitle").textContent = originalName;
    setStatus($("#editStatus"), "");
    $("#textWorkspace").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus($("#editStatus"), error.message, true);
  }
});

$("#renderForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#renderStatus");
  setStatus(status, "Unlocking and rendering Markdown...");
  try {
    const file = form.asset.files[0];
    if (!file) throw new Error("Choose a Markdown lock file first.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    const originalName = decoded.header.original_name || stripLockExtension(file.name);
    requireMarkdownName(originalName);
    validatePin(form.pin.value);
    const keyBytes = await keyFromShardFiles(form.shards.files, form.pin.value, decoded.header);
    const plain = await unlockDecoded(decoded, keyBytes);
    const pages = parseMarkdownPages(decodeText(plain));
    const renderedPages = await Promise.all(pages.map(async (page) => {
      const response = await fetch("/api/render", {
        method: "POST",
        headers: { "Content-Type": "text/markdown; charset=utf-8" },
        body: page.markdown,
      });
      if (!response.ok) throw new Error((await response.text()).trim() || "Markdown rendering failed.");
      return { ...page, html: await response.text() };
    }));
    renderMarkdownPages(renderedPages);
    $("#renderTitle").textContent = originalName;
    makeRenderedListItemsCopyable();
    setStatus(status, `Markdown rendered as ${pages.length} ${pages.length === 1 ? "page" : "pages"}.`);
  } catch (error) {
    setStatus(status, error.message, true);
  }
});

$("#alphabetizeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#alphabetizeStatus");
  setStatus(status, "Unlocking and alphabetizing Markdown sections...");
  try {
    const file = form.asset.files[0];
    if (!file) throw new Error("Choose a Markdown lock file first.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    const originalName = decoded.header.original_name || stripLockExtension(file.name);
    requireMarkdownName(originalName);
    validatePin(form.pin.value);
    const keyBytes = await keyFromShardFiles(form.shards.files, form.pin.value, decoded.header);
    const plain = await unlockDecoded(decoded, keyBytes);
    const { markdown, count } = alphabetizeMarkdownSections(decodeText(plain));
    const locked = await lockBytes(textBytes(markdown), {
      kind: "raw", keyBytes, pin: true, shardIds: decoded.header.shard_ids,
    }, originalName);
    renderDownloads($("#alphabetizeDownloads"), [asset(
      alphabetizedLockName(originalName), locked, "Alphabetized Markdown lock file",
      "Protected by the same PIN and key bundle.",
    )]);
    setStatus(status, `Alphabetized ${count} Markdown sections. The new lock file is ready.`);
  } catch (error) {
    setStatus(status, error.message, true);
  }
});

function activateTab(name) {
  if (!["intro", "encrypt", "decrypt", "edit", "render", "alphabetize", "markdown-docs"].includes(name)) name = "intro";
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
      selectedBundle = selectedFiles.find((file) => file.name.toLowerCase().endsWith(".bundle"));
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
      : ["decryptAsset", "editAsset", "renderAsset", "alphabetizeAsset"].includes(inputId) ? "No lock file selected." : "No file selected.";
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

function syncRenderSubmit() {
  const form = $("#renderForm");
  $("#renderSubmit").disabled = !(renderLockSupported && form.asset.files[0] && form.pin.value && form.shards.files.length);
}

function syncAlphabetizeSubmit() {
  const form = $("#alphabetizeForm");
  $("#alphabetizeSubmit").disabled = !(alphabetizeLockSupported && form.asset.files[0] && form.pin.value && form.shards.files.length);
}

async function inspectAlphabetizeLockFile() {
  const form = $("#alphabetizeForm");
  const file = form.asset.files[0];
  alphabetizeLockSupported = false;
  syncAlphabetizeSubmit();
  if (!file) {
    $("#alphabetizeCredentialSummary").textContent = "The Markdown must use titled page markers with sections beginning with single # headings.";
    return;
  }
  try {
    if (!file.name.toLowerCase().endsWith(".lock")) throw new Error("Choose a Cleaver .lock file.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    const originalName = decoded.header.original_name || stripLockExtension(file.name);
    requireMarkdownName(originalName);
    alphabetizeLockSupported = decoded.header.kdf === "pin-sha256";
    if (!alphabetizeLockSupported) throw new Error("This lock uses an unsupported unlock method.");
    $("#alphabetizeCredentialSummary").textContent = `${originalName} is ready. Enter its PIN and select its key bundle.`;
    setStatus($("#alphabetizeStatus"), "Markdown lock metadata read. Ready for credentials.");
  } catch (error) {
    $("#alphabetizeCredentialSummary").textContent = "Only valid Cleaver locks containing Markdown files are supported.";
    setStatus($("#alphabetizeStatus"), error.message, true);
  }
  syncAlphabetizeSubmit();
}

async function inspectRenderLockFile() {
  const form = $("#renderForm");
  const file = form.asset.files[0];
  renderLockSupported = false;
  syncRenderSubmit();
  if (!file) {
    $("#renderCredentialSummary").textContent = "Only lock files whose original file is Markdown can be rendered.";
    return;
  }
  try {
    if (!file.name.toLowerCase().endsWith(".lock")) throw new Error("Choose a Cleaver .lock file.");
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    const originalName = decoded.header.original_name || stripLockExtension(file.name);
    requireMarkdownName(originalName);
    renderLockSupported = decoded.header.kdf === "pin-sha256";
    if (!renderLockSupported) throw new Error("This lock uses an unsupported unlock method.");
    $("#renderCredentialSummary").textContent = `${originalName} is a Markdown lock. Enter its PIN and select its key bundle.`;
    setStatus($("#renderStatus"), "Markdown lock metadata read. Ready for credentials.");
  } catch (error) {
    $("#renderCredentialSummary").textContent = "Only valid Cleaver locks containing Markdown files are supported.";
    setStatus($("#renderStatus"), error.message, true);
  }
  syncRenderSubmit();
}

async function inspectEditLockFile() {
  const file = $("#editForm").asset.files[0];
  editLockSupported = false;
  if (!file) return syncEditSubmit();
  try {
    const decoded = decodeLock(new Uint8Array(await file.arrayBuffer()));
    editLockSupported = decoded.header.kdf === "pin-sha256";
    setStatus($("#editStatus"), editLockSupported ? `${decoded.header.original_name || stripLockExtension(file.name)} is ready for credentials.` : "This lock uses an unsupported unlock method.", !editLockSupported);
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

function requireMarkdownName(name) {
  if (!/\.(md|markdown)$/i.test(baseName(name))) {
    throw new Error("This lock file does not contain a Markdown file.");
  }
}

function parseMarkdownPages(text) {
  const lines = text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n");
  const marker = /^\s*={3,}\s*$/;
  const pages = [];
  let index = 0;

  while (index < lines.length && !lines[index].trim()) index++;
  if (!marker.test(lines[index] || "")) {
    throw new Error("Markdown must begin with a page marker: ===, a page title, and another === line.");
  }

  while (index < lines.length) {
    if (!marker.test(lines[index] || "")) {
      throw new Error(`Expected a page marker on line ${index + 1}.`);
    }
    const title = (lines[index + 1] || "").trim();
    if (!title || marker.test(title)) throw new Error(`Page title on line ${index + 2} is missing.`);
    if (!marker.test(lines[index + 2] || "")) {
      throw new Error(`Page title "${title}" must be followed by a line of at least three equals signs.`);
    }

    const contentStart = index + 3;
    index = contentStart;
    while (index < lines.length && !marker.test(lines[index])) index++;
    pages.push({ title, markdown: lines.slice(contentStart, index).join("\n").trim() });
  }

  return pages;
}

function renderMarkdownPages(pages) {
  const output = $("#renderOutput");
  const sidebar = $("#renderDocumentSidebar");
  const pageLinks = $("#renderPageNavigationLinks");
  const sectionNavigations = $("#renderSectionNavigations");
  output.replaceChildren();
  pageLinks.replaceChildren();
  sectionNavigations.replaceChildren();

  pages.forEach((page, pageIndex) => {
    const panel = document.createElement("section");
    panel.className = "rendered-page";
    panel.id = `rendered-page-${pageIndex + 1}`;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-label", page.title);
    panel.hidden = pageIndex !== 0;

    const title = document.createElement("h2");
    title.className = "rendered-page-title";
    title.textContent = page.title;
    const contents = document.createElement("div");
    contents.className = "rendered-page-contents";
    contents.innerHTML = page.html;
    panel.append(title, contents);
    output.append(panel);

    const sectionNavigation = buildRenderNavigation(contents, pageIndex);
    sectionNavigation.hidden = pageIndex !== 0 || sectionNavigation.hidden;
    sectionNavigations.append(sectionNavigation);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "render-page-tab";
    button.textContent = page.title;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", panel.id);
    button.setAttribute("aria-selected", String(pageIndex === 0));
    button.addEventListener("click", () => activateRenderedPage(pageIndex));
    pageLinks.append(button);
  });

  sidebar.hidden = pages.length === 0;
}

function activateRenderedPage(activeIndex) {
  $("#renderOutput").querySelectorAll(".rendered-page").forEach((page, index) => {
    page.hidden = index !== activeIndex;
  });
  $("#renderPageNavigationLinks").querySelectorAll(".render-page-tab").forEach((button, index) => {
    button.setAttribute("aria-selected", String(index === activeIndex));
  });
  $("#renderSectionNavigations").querySelectorAll(".render-navigation").forEach((navigation, index) => {
    navigation.hidden = index !== activeIndex || navigation.dataset.empty === "true";
  });
}

function buildRenderNavigation(contents, pageIndex) {
  const navigation = document.createElement("nav");
  const headings = Array.from(contents.querySelectorAll("h1"));
  navigation.className = "render-navigation";
  navigation.dataset.empty = String(headings.length === 0);
  navigation.setAttribute("aria-label", "Sections on this page");
  const label = document.createElement("strong");
  label.textContent = "On this page";
  const links = document.createElement("div");
  links.className = "render-navigation-links";

  headings.forEach((heading, index) => {
    const id = `document-page-${pageIndex + 1}-section-${index + 1}`;
    heading.id = id;
    heading.tabIndex = -1;
    const link = document.createElement("a");
    link.href = `#${id}`;
    link.textContent = heading.textContent.trim() || `Section ${index + 1}`;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      heading.scrollIntoView({ behavior: "smooth", block: "start" });
      heading.focus({ preventScroll: true });
    });
    links.append(link);
  });

  navigation.append(label, links);
  navigation.hidden = headings.length === 0;
  return navigation;
}

function makeRenderedListItemsCopyable() {
  const items = $("#renderOutput").querySelectorAll("li");
  items.forEach((item) => {
    const copyText = item.textContent.trim();
    const button = document.createElement("button");
    button.className = "copy-list-item";
    button.type = "button";
    button.textContent = "Copy";
    button.setAttribute("aria-label", `Copy list item: ${copyText}`);
    button.addEventListener("click", async () => {
      try {
        await copyTextToClipboard(copyText);
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = "Copy"; }, 1500);
      } catch {
        button.textContent = "Copy failed";
        window.setTimeout(() => { button.textContent = "Copy"; }, 1500);
      }
    });
    item.append(button);
  });
}

async function copyTextToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const input = document.createElement("textarea");
  input.value = text;
  input.setAttribute("readonly", "");
  input.className = "clipboard-fallback";
  document.body.append(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  if (!copied) throw new Error("Clipboard copy failed.");
}

function alphabetizeMarkdownSections(text) {
  const pages = parseMarkdownPages(text);
  let count = 0;
  const markdown = pages.map((page) => {
    const alphabetized = alphabetizeMarkdownPage(page.markdown);
    count += alphabetized.count;
    return `===\n${page.title}\n===\n\n${alphabetized.markdown.trimEnd()}`;
  }).join("\n\n") + "\n";
  return { markdown, count };
}

function alphabetizeMarkdownPage(text) {
  const normalized = text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  const sections = [];
  let current = null;

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const heading = line.match(/^#\s+(.+?)\s*#*\s*$/);
    if (heading) {
      const title = heading[1].trim();
      if (!title) throw new Error(`Markdown heading on line ${index + 1} is empty.`);
      current = { title, index: sections.length, lines: [line] };
      sections.push(current);
      continue;
    }
    if (/^#{2,6}(?:\s|$)/.test(line) || index > 0 && /^(?:=+|-+)\s*$/.test(line) && lines[index - 1].trim()) {
      throw new Error(`Only single # headings are allowed (line ${index + 1}).`);
    }
    if (!current) {
      if (line.trim()) throw new Error("Markdown content must begin with a # heading.");
      continue;
    }
    current.lines.push(line);
  }

  if (!sections.length) throw new Error("The Markdown file has no # headings to alphabetize.");
  const collator = new Intl.Collator(undefined, { sensitivity: "base", usage: "sort" });
  sections.sort((left, right) => collator.compare(left.title, right.title) || left.index - right.index);
  const markdown = sections.map((section) => section.lines.join("\n").trimEnd()).join("\n\n") + "\n";
  return { markdown, count: sections.length };
}

function closeEditor() {
  editorState = null;
  $("#textEditor").value = "";
  $("#editorPageTitle").value = "";
  $("#editorPageNavigationLinks").replaceChildren();
  $("#editorPageNavigation").hidden = true;
  $("#editorPageTitleField").hidden = true;
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
  setStatus($("#exportStatus"), "Encrypting edited text...");
  try {
    saveActiveEditorPage();
    const text = editorState.paged ? serializeMarkdownPages(editorState.pages) : editorState.pages[0].markdown;
    const plain = textBytes(text);
    const locked = await lockBytes(plain, { kind: "raw", keyBytes: editorState.keyBytes, pin: true, shardIds: editorState.shardIds }, editorState.originalName);
    const name = outputName(editorState.originalName, ".lock");
    renderDownloads($("#editDownloads"), [asset(name, locked, "Edited lock file", "Protected by the same PIN and key bundle.")]);
    setStatus($("#exportStatus"), "New lock file ready. Your original lock file was not changed.");
  } catch (error) {
    setStatus($("#exportStatus"), error.message, true);
  }
}

function renderEditorPages() {
  const navigation = $("#editorPageNavigation");
  const links = $("#editorPageNavigationLinks");
  links.replaceChildren();
  navigation.hidden = !editorState.paged;
  $("#editorPageTitleField").hidden = !editorState.paged;

  if (editorState.paged) {
    editorState.pages.forEach((page, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "editor-page-tab";
      button.textContent = page.title;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(index === editorState.activePageIndex));
      button.addEventListener("click", () => activateEditorPage(index));
      links.append(button);
    });
  }

  loadActiveEditorPage();
}

function activateEditorPage(index) {
  if (!editorState || index === editorState.activePageIndex) return;
  try {
    saveActiveEditorPage();
  } catch (error) {
    setStatus($("#exportStatus"), error.message, true);
    return;
  }
  editorState.activePageIndex = index;
  $("#editorPageNavigationLinks").querySelectorAll(".editor-page-tab").forEach((button, buttonIndex) => {
    button.setAttribute("aria-selected", String(buttonIndex === index));
  });
  loadActiveEditorPage();
  setStatus($("#exportStatus"), "");
}

function addEditorPage() {
  if (!editorState?.paged) return;
  try {
    saveActiveEditorPage();
  } catch (error) {
    setStatus($("#exportStatus"), error.message, true);
    return;
  }

  const existingTitles = new Set(editorState.pages.map((page) => page.title.toLocaleLowerCase()));
  let title = "New page";
  let suffix = 2;
  while (existingTitles.has(title.toLocaleLowerCase())) {
    title = `New page ${suffix}`;
    suffix += 1;
  }

  editorState.pages.push({ title, markdown: "" });
  editorState.activePageIndex = editorState.pages.length - 1;
  renderEditorPages();
  setStatus($("#exportStatus"), "New page added. It will be included when you export.");
  $("#editorPageTitle").focus();
  $("#editorPageTitle").select();
}

function loadActiveEditorPage() {
  const page = editorState.pages[editorState.activePageIndex];
  $("#textEditor").value = page.markdown;
  $("#editorPageTitle").value = page.title;
  $("#textEditor").setAttribute("aria-label", editorState.paged ? `${page.title} page contents` : "File contents");
}

function saveActiveEditorPage() {
  const page = editorState.pages[editorState.activePageIndex];
  page.markdown = $("#textEditor").value;
  if (!editorState.paged) return;
  if (page.markdown.split(/\r?\n/).some((line) => /^\s*={3,}\s*$/.test(line))) {
    throw new Error("Page content cannot contain a line of three or more equals signs because it is reserved for page markers.");
  }
  const title = $("#editorPageTitle").value.trim();
  if (!title) throw new Error("Every Markdown page must have a title.");
  if (/^\s*={3,}\s*$/.test(title)) throw new Error("A page title cannot be an equals-sign marker.");
  page.title = title;
  const button = $("#editorPageNavigationLinks").querySelectorAll(".editor-page-tab")[editorState.activePageIndex];
  if (button) button.textContent = title;
}

function syncEditorPageTitle() {
  if (!editorState?.paged) return;
  const title = $("#editorPageTitle").value.trim();
  const button = $("#editorPageNavigationLinks").querySelectorAll(".editor-page-tab")[editorState.activePageIndex];
  if (button) button.textContent = title || "Untitled page";
}

function serializeMarkdownPages(pages) {
  return pages.map((page) => `===\n${page.title}\n===\n\n${page.markdown.trim()}`).join("\n\n") + "\n";
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

function alphabetizedLockName(name) {
  const clean = baseName(name);
  const dot = clean.lastIndexOf(".");
  return (dot > 0 ? clean.slice(0, dot) : clean) + "-alphabetized.lock";
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
