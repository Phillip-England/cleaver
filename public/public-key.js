const $ = (selector) => document.querySelector(selector);
const token = document.body.dataset.keyToken;
let state = null;

const dropzone = $("#publicDropzone");
["dragenter", "dragover"].forEach((name) => dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.add("dragover"); }));
["dragleave", "drop"].forEach((name) => dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.remove("dragover"); }));
dropzone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const transfer = new DataTransfer(); transfer.items.add(file); $("#publicLockFile").files = transfer.files;
  $("#publicLockFile").dispatchEvent(new Event("change"));
});
$("#publicLockFile").addEventListener("change", () => {
  const file = $("#publicLockFile").files[0];
  $("#publicLockMeta").textContent = file ? file.name : "No lock file selected.";
});

$("#publicUnlockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus($("#publicStatus"), "Unlocking...");
  try {
    const lock = $("#publicLockFile").files[0];
    const pin = $("#publicPin").value;
    const form = new FormData();
    form.append("lock", lock);
    form.append("pin", pin);
    const response = await fetch(`/api/key/${token}/open`, { method: "POST", body: form });
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    if (!/\.csv$/i.test(result.name)) throw new Error("This lock does not contain a CSV file.");
    state = {
      pin,
      name: result.name,
      lockData: await fileBase64(lock),
      rows: normalizeRows(parseCSV(new TextDecoder("utf-8", { fatal: true }).decode(base64Bytes(result.data)))),
    };
    $("#publicWorkspace").hidden = false;
    $("#publicEditorTitle").textContent = result.name;
    renderGrid();
    setStatus($("#publicStatus"), "Unlocked. Edit below, then download a new lock.");
  } catch (error) {
    $("#publicWorkspace").hidden = true;
    setStatus($("#publicStatus"), error.message, true);
  }
});

$("#publicRelock").addEventListener("click", async () => {
  if (!state) return;
  setStatus($("#publicRelockStatus"), "Creating new lock...");
  try {
    const response = await fetch(`/api/key/${token}/relock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin: state.pin, lock_data: state.lockData, csv: serializeCSV(state.rows) }),
    });
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([base64Bytes(result.lock_data)], { type: "application/octet-stream" }));
    link.download = result.name;
    link.click();
    setStatus($("#publicRelockStatus"), "New lock downloaded. Nothing was saved on this page.");
  } catch (error) {
    setStatus($("#publicRelockStatus"), error.message, true);
  }
});

$("#publicAddRow").addEventListener("click", () => {
  state.rows.push(Array(state.rows[0]?.length || 1).fill(""));
  renderGrid();
});

$("#publicAddColumn").addEventListener("click", () => {
  state.rows.forEach((row) => row.push(""));
  renderGrid();
});

function renderGrid() {
  const grid = $("#publicGrid");
  grid.replaceChildren();
  const columns = state.rows[0]?.length || 1;
  const thead = document.createElement("thead");
  const heading = document.createElement("tr");
  heading.append(document.createElement("th"));
  for (let col = 0; col < columns; col++) {
    const th = document.createElement("th"); th.textContent = columnName(col); heading.append(th);
  }
  thead.append(heading);
  const tbody = document.createElement("tbody");
  state.rows.forEach((row, rowIndex) => {
    const tr = document.createElement("tr");
    const th = document.createElement("th"); th.textContent = String(rowIndex + 1); tr.append(th);
    row.forEach((cell, colIndex) => {
      const td = document.createElement("td");
      const input = document.createElement("input"); input.className = "sheet-cell"; input.value = cell;
      input.addEventListener("input", () => { state.rows[rowIndex][colIndex] = input.value; });
      td.append(input); tr.append(td);
    });
    tbody.append(tr);
  });
  grid.append(thead, tbody);
  $("#publicEditorMeta").textContent = `${state.rows.length} rows x ${columns} columns`;
}

function parseCSV(text) {
  const rows = []; let row = []; let cell = ""; let quoted = false;
  for (let i = text.startsWith("\uFEFF") ? 1 : 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"' && !cell) quoted = true;
    else if (char === ",") { row.push(cell); cell = ""; }
    else if (char === "\n" || char === "\r") { row.push(cell); rows.push(row); row = []; cell = ""; if (char === "\r" && text[i + 1] === "\n") i++; }
    else cell += char;
  }
  if (quoted) throw new Error("Invalid CSV: quoted cell is not closed.");
  if (cell || row.length || !rows.length) { row.push(cell); rows.push(row); }
  return rows;
}

function normalizeRows(rows) {
  const width = Math.max(1, ...rows.map((row) => row.length));
  return rows.map((row) => row.concat(Array(width - row.length).fill("")));
}

function serializeCSV(rows) {
  return rows.map((row) => row.map((value) => /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value).join(",")).join("\n") + "\n";
}

function columnName(index) {
  let name = ""; let value = index + 1;
  while (value) { name = String.fromCharCode(65 + ((value - 1) % 26)) + name; value = Math.floor((value - 1) / 26); }
  return name;
}

function base64Bytes(value) {
  const binary = atob(value); const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function fileBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer()); let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function setStatus(element, text, error = false) {
  element.className = error ? "status err" : "status";
  element.textContent = text.trim();
}
