// ---- Monitoring real-time: ambil flow baru tiap 2 detik ----
(function () {
  const body = document.getElementById("flow-body");
  if (!body) return;
  const warna = { BENIGN: "green", Syn: "red", DrDoS_UDP: "red" };
  const MAX = 8;
  let total = 147, serangan = 12;

  function baris(f) {
    const c = f.prediksi === "BENIGN" ? "green" : (f.conf >= 0.9 ? "red" : "yellow");
    const tr = document.createElement("tr");
    tr.className = "click";
    tr.innerHTML = `<td class="mono">${f.waktu}</td><td class="mono">${f.src}</td>
      <td class="mono">${f.dst}</td><td class="mono">${f.proto}</td>
      <td class="${c}">${f.prediksi}</td><td>${f.conf.toFixed(2)}</td>`;
    return tr;
  }

  async function tarik() {
    try {
      const res = await fetch("/api/flows");
      const flows = await res.json();
      flows.forEach(f => {
        body.prepend(baris(f));
        if (f.prediksi !== "BENIGN") serangan++;
      });
      while (body.children.length > MAX) body.lastChild.remove();
      total = 130 + Math.floor(Math.random() * 40);
      document.getElementById("fps").textContent = total;
      document.getElementById("atk").textContent = serangan;
      document.getElementById("lat").textContent = 30 + Math.floor(Math.random() * 18) + " ms";
    } catch (e) { /* abaikan error sementara */ }
  }
  tarik();
  setInterval(tarik, 2000);
})();

// ---- Slider threshold ----
const slider = document.getElementById("threshold");
if (slider) {
  const out = document.getElementById("threshold-val");
  slider.addEventListener("input", () => (out.textContent = slider.value + "%"));
}

// ---- Dialog tambah pengguna ----
const dlg = document.getElementById("dlg-user");
const openBtn = document.getElementById("btn-add-user");
if (dlg && openBtn) {
  openBtn.addEventListener("click", () => dlg.showModal());
  document.getElementById("dlg-close").addEventListener("click", () => dlg.close());
}

// ---- Auto submit untuk filter ----
document.querySelectorAll("form.filters select").forEach(s =>
  s.addEventListener("change", () => s.form.submit()));

// ---- Render bar grafik distribusi (tanpa inline style di HTML) ----
function renderHbars() {
  document.querySelectorAll(".hbar .t i[data-w]").forEach(el => {
    el.style.width = el.getAttribute("data-w") + "%";
    el.style.backgroundColor = el.getAttribute("data-c");
  });
}
renderHbars();
document.addEventListener("DOMContentLoaded", renderHbars);
