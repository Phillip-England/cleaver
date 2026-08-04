const $ = (selector) => document.querySelector(selector);

let keys = [];
let editorState = null;

document.querySelectorAll("[data-admin-tab]").forEach((button) => {
  button.addEventListener("click", () => activateAdminTab(button.dataset.adminTab));
});

$("#adminEncryptForm").addEventListener("submit", encryptArtifact);
$("#unlockForm").addEventListener("submit", unlockForEdit);
$("#decryptDownload").addEventListener("click", decryptDownload);
$("#adminRelock").addEventListener("click", relockCSV);
$("#adminAddRow").addEventListener("click", addRow);
$("#adminAddColumn").addEventListener("click", addColumn);

refreshArtifacts();

function activateAdminTab(name) {
  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.adminTab === name);
  });
  ["registry", "encrypt", "unlock"].forEach((id) => {
    $(`#admin-${id}`).classList.toggle("active", id === name);
  });
}

async function encryptArtifact(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#adminEncryptStatus");
  setStatus(status, "Encrypting and storing...");
  try {
    const result = await postForm("/api/admin/encrypt", form);
    form.reset();
    setStatus(status, "Ready. Download both recovery files and save the public link.");
    renderCreatedLock(result);
    await refreshArtifacts();
  } catch (error) {
    setStatus(status, error.message, true);
  }
}

function renderCreatedLock(result) {
  const root = $("#lockCreated");
  root.hidden = false;
  root.innerHTML = `<h3>Recovery kit ready</h3><p>Download both files and save the public link. The key remains in this portal, but your downloaded copy lets you recover if you lose portal access.</p><div class="actions"><a class="primary">Download lock file</a><a class="secondary">Download backup key</a><a class="secondary" target="_blank" rel="noopener">Open public unlock link</a><button class="secondary copy-created-link" type="button">Copy public link</button></div>`;
  const links = root.querySelectorAll("a");
  links[0].href = downloadBase64(result.lock_data, result.lock_name);
  links[0].download = result.lock_name;
  links[1].href = result.key_download_url;
  links[1].download = result.key_name;
  links[2].href = result.public_url;
  root.querySelector(".copy-created-link").addEventListener("click", async (event) => {
    await navigator.clipboard.writeText(new URL(result.public_url, location.origin).href);
    event.currentTarget.textContent = "Copied";
  });
}

async function unlockForEdit(event) {
  event.preventDefault();
  const status = $("#unlockStatus");
  setStatus(status, "Unlocking...");
  try {
    const result = await unlockSelected();
    const text = decodeBase64Text(result.data);
    if (!/\.csv$/i.test(result.name)) throw new Error("The unlocked asset is not a CSV file.");
    editorState = {
      keyId: Number($("#keySelect").value),
      lockData: await fileBase64($("#lockFile").files[0]),
      pin: $("#unlockPin").value,
      name: result.name,
      rows: normalizeCSVRows(parseCSV(text)),
    };
    $("#adminWorkspace").hidden = false;
    $("#adminEditorTitle").textContent = result.name;
    renderGrid();
    setStatus(status, "Unlocked. Edit the spreadsheet and relock when done.");
  } catch (error) {
    $("#adminWorkspace").hidden = true;
    setStatus(status, error.message, true);
  }
}

async function decryptDownload() {
  const status = $("#unlockStatus");
  setStatus(status, "Decrypting...");
  try {
    const result = await unlockSelected();
    const bytes = base64Bytes(result.data);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    link.download = result.name || "decrypted-asset";
    link.click();
    URL.revokeObjectURL(link.href);
    setStatus(status, "Decrypted download started.");
  } catch (error) {
    setStatus(status, error.message, true);
  }
}

async function relockCSV() {
  if (!editorState) return;
  const status = $("#relockStatus");
  setStatus(status, "Creating your new lock...");
  try {
    const result = await postJSON("/api/admin/relock", {
      key_id: editorState.keyId,
      lock_data: editorState.lockData,
      pin: editorState.pin,
      csv: serializeCSV(editorState.rows),
    });
    const link = document.createElement("a");
    link.href = downloadBase64(result.lock_data, result.name);
    link.download = result.name;
    link.click();
    setStatus(status, "New lock downloaded. The uploaded lock was not stored or changed.");
  } catch (error) {
    setStatus(status, error.message, true);
  }
}

async function unlockSelected() {
  const lock = $("#lockFile").files[0];
  if (!lock) throw new Error("Choose a lock file.");
  const pin = $("#unlockPin").value;
  if (!pin) throw new Error("PIN is required.");
  const form = new FormData();
  form.append("key_id", $("#keySelect").value);
  form.append("pin", pin);
  form.append("lock", lock);
  const response = await fetch("/api/admin/open", { method: "POST", body: form });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function refreshArtifacts() {
  const data = await getJSON("/api/admin/keys");
  keys = data.keys || [];
  renderKeyList();
  renderKeySelect();
}

function renderKeyList() {
  const root = $("#keyList");
  root.replaceChildren();
  if (!keys.length) { root.innerHTML = `<div class="panel empty">No keys yet. Upload a CSV to create your first lock and key.</div>`; return; }
  for (const item of keys) {
    const row = document.createElement("div"); row.className = "artifact-row";
    row.innerHTML = `<div><strong></strong><small></small></div><div class="actions"><a class="secondary download-key">Download key</a><a class="secondary public-link">Open public link</a><button class="secondary copy-link" type="button">Copy link</button><button class="secondary delete-key" type="button">Delete</button></div>`;
    row.querySelector("strong").textContent = item.name; row.querySelector("small").textContent = item.filename;
    const publicURL = `${location.origin}/key/${item.token}`;
    const keyLink = row.querySelector(".download-key");
    keyLink.href = `/api/admin/keys/${item.id}/download`;
    keyLink.download = item.filename;
    const publicLink = row.querySelector(".public-link");
    publicLink.href = publicURL;
    publicLink.target = "_blank";
    publicLink.rel = "noopener";
    row.querySelector(".copy-link").addEventListener("click", async (event) => { await navigator.clipboard.writeText(publicURL); event.currentTarget.textContent = "Copied"; });
    row.querySelector(".delete-key").addEventListener("click", async () => { await fetch(`/api/admin/keys/${item.id}`, { method: "DELETE" }); await refreshArtifacts(); });
    root.append(row);
  }
}

function renderKeySelect() {
  const select = $("#keySelect");
  const current = select.value;
  select.innerHTML = "";
  keys.forEach((item) => {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = item.name;
      select.append(option);
  });
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

function renderGrid(focusRow = 0, focusCol = 0) {
  const grid = $("#adminGrid");
  grid.replaceChildren();
  const columnCount = editorState.rows[0]?.length || 1;
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(document.createElement("th"));
  for (let col = 0; col < columnCount; col++) {
    const th = document.createElement("th");
    th.textContent = columnName(col);
    headRow.append(th);
  }
  thead.append(headRow);
  const tbody = document.createElement("tbody");
  editorState.rows.forEach((row, rowIndex) => {
    const tr = document.createElement("tr");
    const rowHead = document.createElement("th");
    rowHead.textContent = String(rowIndex + 1);
    tr.append(rowHead);
    row.forEach((cell, colIndex) => {
      const td = document.createElement("td");
      const input = document.createElement("input");
      input.className = "sheet-cell";
      input.value = cell;
      input.dataset.row = String(rowIndex);
      input.dataset.col = String(colIndex);
      input.addEventListener("input", (event) => {
        editorState.rows[rowIndex][colIndex] = event.currentTarget.value;
      });
      td.append(input);
      tr.append(td);
    });
    tbody.append(tr);
  });
  grid.append(thead, tbody);
  $("#adminEditorMeta").textContent = `${editorState.rows.length} rows x ${columnCount} columns`;
  grid.querySelector(`[data-row="${focusRow}"][data-col="${focusCol}"]`)?.focus();
}

function addRow() {
  if (!editorState) return;
  editorState.rows.push(Array.from({ length: editorState.rows[0]?.length || 1 }, () => ""));
  renderGrid(editorState.rows.length - 1, 0);
}

function addColumn() {
  if (!editorState) return;
  editorState.rows.forEach((row) => row.push(""));
  renderGrid(0, editorState.rows[0].length - 1);
}

async function postForm(url, form) {
  const response = await fetch(url, { method: "POST", body: new FormData(form) });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function getJSON(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
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
    } else if (char === "\"") {
      if (cell.length === 0) quoted = true;
      else throw new Error("Invalid CSV: quotes must begin a cell or be escaped.");
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
  return rows.length ? rows.map((row) => row.concat(Array(Math.max(0, columnCount - row.length)).fill(""))) : [[""]];
}

function serializeCSV(rows) {
  return rows.map((row) => row.map(escapeCSVCell).join(",")).join("\n") + "\n";
}

function escapeCSVCell(value) {
  const text = String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, "\"\"")}"`;
  return text;
}

function columnName(index) {
  let name = "";
  let value = index + 1;
  while (value > 0) {
    const remainder = (value - 1) % 26;
    name = String.fromCharCode(65 + remainder) + name;
    value = Math.floor((value - 1) / 26);
  }
  return name;
}

function decodeBase64Text(value) {
  return new TextDecoder("utf-8", { fatal: true }).decode(base64Bytes(value));
}

function base64Bytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function downloadBase64(value) {
  return URL.createObjectURL(new Blob([base64Bytes(value)], { type: "application/octet-stream" }));
}

async function fileBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function setStatus(el, text, error = false) {
  el.className = error ? "status err" : "status";
  el.textContent = text.trim();
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
