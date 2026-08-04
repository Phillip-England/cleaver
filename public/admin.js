const $ = (selector) => document.querySelector(selector);

let artifacts = [];
let locks = [];
let editorState = null;

document.querySelectorAll("[data-admin-tab]").forEach((button) => {
  button.addEventListener("click", () => activateAdminTab(button.dataset.adminTab));
});

$("#adminEncryptForm").addEventListener("submit", encryptArtifact);
$("#bundleQRForm").addEventListener("submit", createBundleQR);
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
  ["registry", "encrypt", "bundle", "unlock"].forEach((id) => {
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
    setStatus(status, "Lock created. Download the bundle before leaving this page.");
    renderCreatedLock(result);
    await refreshArtifacts();
  } catch (error) {
    setStatus(status, error.message, true);
  }
}

function renderCreatedLock(result) {
  const root = $("#lockCreated");
  root.hidden = false;
  root.innerHTML = `<h3>Lock ready</h3><img class="lock-qr" alt="QR code for lock link"><div class="field"><label>Access link</label><input class="input" readonly></div><div class="actions"><a class="secondary" target="_blank" rel="noopener">Open link</a><a class="secondary" download="lock-qr.png">Download lock QR</a><a class="primary">Download bundle</a></div>`;
  root.querySelector("img").src = result.qr_url;
  root.querySelector("input").value = result.url;
  const links = root.querySelectorAll("a");
  links[0].href = result.url; links[1].href = result.qr_url; links[2].href = `/api/admin/artifacts/${result.bundle_id}/download`;
}

async function createBundleQR(event) {
  event.preventDefault();
  const status = $("#bundleQRStatus");
  setStatus(status, "Creating QR code...");
  try {
    const response = await fetch("/api/admin/bundle-qr", { method: "POST", body: new FormData(event.currentTarget) });
    if (!response.ok) throw new Error(await response.text());
    const url = URL.createObjectURL(await response.blob());
    const result = $("#bundleQRResult");
    const old = $("#bundleQRImage").src;
    if (old.startsWith("blob:")) URL.revokeObjectURL(old);
    $("#bundleQRImage").src = url; $("#bundleQRDownload").href = url; result.hidden = false;
    setStatus(status, "Bundle QR is ready.");
  } catch (error) { setStatus(status, error.message, true); }
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
      assetIds: selectedAssetIds(),
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
  setStatus(status, "Relocking into the registry...");
  try {
    await postJSON("/api/admin/relock", {
      asset_ids: editorState.assetIds,
      pin: editorState.pin,
      csv: serializeCSV(editorState.rows),
    });
    setStatus(status, "Registry lock updated.");
    await refreshArtifacts();
  } catch (error) {
    setStatus(status, error.message, true);
  }
}

async function unlockSelected() {
  const assetIds = selectedAssetIds();
  if (assetIds[0] === assetIds[1]) throw new Error("Choose two different artifacts.");
  const pin = $("#unlockPin").value;
  if (!pin) throw new Error("PIN is required.");
  return postJSON("/api/admin/decrypt", { asset_ids: assetIds, pin });
}

function selectedAssetIds() {
  return [Number($("#assetA").value), Number($("#assetB").value)];
}

async function refreshArtifacts() {
  const data = await getJSON("/api/admin/artifacts");
  artifacts = data.artifacts || [];
  locks = data.locks || [];
  renderLockList();
  renderArtifactList();
  renderArtifactSelects();
}

function renderLockList() {
  const root = $("#lockList");
  root.replaceChildren();
  if (!locks.length) { root.innerHTML = `<div class="panel empty">No locks yet. Create one from a CSV.</div>`; return; }
  for (const item of locks) {
    const url = `${location.origin}/l/${item.token}`;
    const row = document.createElement("div"); row.className = "artifact-row";
    row.innerHTML = `<div><strong></strong><small></small></div><div class="actions"><button class="secondary" type="button">Copy link</button><a class="secondary" target="_blank" rel="noopener">Open</a><a class="secondary" download="lock-qr.png">QR code</a></div>`;
    row.querySelector("strong").textContent = item.name; row.querySelector("small").textContent = item.filename;
    const [copy, open, qr] = row.querySelectorAll("button,a");
    copy.addEventListener("click", async () => { await navigator.clipboard.writeText(url); copy.textContent = "Copied"; });
    open.href = url; qr.href = `/api/locks/${item.token}/qr.png`; root.append(row);
  }
}

function renderArtifactList() {
  const root = $("#artifactList");
  if (!root) return;
  root.innerHTML = "";
  if (!artifacts.length) {
    root.innerHTML = `<div class="panel empty">No artifacts stored.</div>`;
    return;
  }
  for (const item of artifacts) {
    const row = document.createElement("div");
    row.className = "artifact-row";
    row.innerHTML = `
      <div>
        <strong></strong>
        <small></small>
      </div>
      <div class="actions">
        <a class="secondary" href="/api/admin/artifacts/${item.id}/download">Download</a>
        <button class="secondary" type="button">Delete</button>
      </div>`;
    row.querySelector("strong").textContent = item.name;
    row.querySelector("small").textContent = `${item.filename} · ${formatBytes(item.size)}`;
    row.querySelector("button").addEventListener("click", async () => {
      await fetch(`/api/admin/artifacts/${item.id}`, { method: "DELETE" });
      await refreshArtifacts();
    });
    root.append(row);
  }
}

function renderArtifactSelects() {
  for (const select of [$("#assetA"), $("#assetB")]) {
    const current = select.value;
    select.innerHTML = "";
    artifacts.forEach((item) => {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = item.name;
      select.append(option);
    });
    if ([...select.options].some((option) => option.value === current)) select.value = current;
  }
  if (artifacts.length > 1 && $("#assetA").value === $("#assetB").value) {
    $("#assetB").selectedIndex = 1;
  }
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

function setStatus(el, text, error = false) {
  el.className = error ? "status err" : "status";
  el.textContent = text.trim();
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
