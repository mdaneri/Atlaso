(() => {
  const form = document.querySelector("[data-network-diagnostics]");
  if (!form) return;
  const check = form.elements.namedItem("check");
  const source = form.elements.namedItem("source");
  const submit = form.querySelector('button[type="submit"]');
  const status = document.querySelector("[data-network-check-status]");
  const syncSource = () => {
    source.disabled = check.value === "dns";
  };
  check.addEventListener("change", syncSource);
  syncSource();
  form.addEventListener("submit", (event) => {
    if (submit.disabled) {
      event.preventDefault();
      return;
    }
    submit.disabled = true;
    status.hidden = false;
  });
  window.addEventListener("pageshow", () => {
    submit.disabled = false;
    status.hidden = true;
    syncSource();
  });

  const grid = document.querySelector("[data-network-check-grid]");
  const fallback = document.getElementById("network-check-fallback");
  if (!grid || !fallback || !window.AtlasoUiPatterns) return;
  const rows = Array.from(fallback.tBodies[0].rows, (row) => ({
    number: Number(row.cells[0].textContent),
    address: row.cells[1].textContent,
    status: row.cells[2].textContent,
    rtt: row.cells[3]?.textContent,
  }));
  const headers = fallback.tHead.rows[0].cells;
  const columns = [
    { title: headers[0].textContent, field: "number", sorter: "number", width: 112 },
    { title: "Address", field: "address", formatter: "plaintext", minWidth: 190 },
    { title: "Status", field: "status", formatter: "plaintext", minWidth: 110 },
  ];
  if (headers[3]) {
    columns.push({ title: headers[3].textContent, field: "rtt", formatter: "plaintext", minWidth: 170 });
  }
  window.AtlasoUiPatterns.createGrid({
    element: grid,
    pattern: "read-only",
    options: { data: rows, columns, index: "number" },
  });
})();
