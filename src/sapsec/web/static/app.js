// Interacciones de la interfaz (sin dependencias externas; compatible con CSP 'self').
(function () {
  "use strict";

  // Envío automático del selector de snapshot
  document.querySelectorAll("select.autosubmit").forEach(function (s) {
    s.addEventListener("change", function () { s.form.submit(); });
  });

  // Filtro de tablas. Sin comodines: «contiene» en toda la fila. Con * o + (como en SAP): el patrón se aplica
  // a cada columna completa (Z* = una columna que empieza con Z). Varios criterios separados por coma.
  function sapPattern(term) {
    var rx = term.replace(/[.^$|?(){}\[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\+/g, ".");
    return new RegExp("^" + rx + "$", "i");
  }
  function rowMatches(tr, terms) {
    if (!terms.length) return true;
    var text = tr.textContent.toLowerCase();
    var cells = Array.prototype.map.call(tr.children, function (c) { return c.textContent.trim(); });
    return terms.some(function (t) {
      if (t.indexOf("*") < 0 && t.indexOf("+") < 0) return text.indexOf(t.toLowerCase()) >= 0;
      var rx = sapPattern(t);
      return cells.some(function (c) {
        return rx.test(c) || c.split(/\s+/).some(function (w) { return rx.test(w); });
      });
    });
  }
  document.querySelectorAll("input.table-filter").forEach(function (inp) {
    inp.addEventListener("input", function () {
      var t = document.getElementById(inp.dataset.target);
      if (!t) return;
      var terms = inp.value.split(",").map(function (x) { return x.trim(); }).filter(Boolean);
      t.querySelectorAll("tr").forEach(function (tr, i) {
        if (i === 0 && tr.querySelector("th")) return;
        tr.style.display = rowMatches(tr, terms) ? "" : "none";
      });
    });
  });

  // Ordenamiento por columna
  document.querySelectorAll("table.sortable").forEach(function (table) {
    var headers = table.querySelectorAll("tr:first-child th");
    headers.forEach(function (th, idx) {
      th.addEventListener("click", function () {
        var rows = Array.prototype.slice.call(table.querySelectorAll("tr")).slice(1);
        var asc = th.dataset.asc !== "1";
        th.dataset.asc = asc ? "1" : "0";
        rows.sort(function (a, b) {
          var x = (a.children[idx] || {}).textContent || "", y = (b.children[idx] || {}).textContent || "";
          var nx = parseFloat(x), ny = parseFloat(y);
          var r = (!isNaN(nx) && !isNaN(ny)) ? nx - ny : x.localeCompare(y, "es");
          return asc ? r : -r;
        });
        rows.forEach(function (r) { table.appendChild(r); });
      });
    });
  });

  // Pestañas
  document.querySelectorAll(".tabs").forEach(function (tabs) {
    tabs.querySelectorAll("a").forEach(function (a) {
      a.addEventListener("click", function (ev) {
        ev.preventDefault();
        tabs.querySelectorAll("a").forEach(function (x) { x.classList.remove("on"); });
        a.classList.add("on");
        var group = tabs.dataset.group;
        document.querySelectorAll(".tab[data-group='" + group + "']").forEach(function (t) {
          t.classList.toggle("on", t.id === a.dataset.tab);
        });
      });
    });
  });

  // Enlaces que abren una pestaña (fuera de la barra de pestañas)
  document.querySelectorAll("a.tablink").forEach(function (a) {
    a.addEventListener("click", function (ev) {
      ev.preventDefault();
      var target = document.querySelector(".tabs a[data-tab='" + a.dataset.tab + "']");
      if (target) { target.click(); target.scrollIntoView({behavior: "smooth", block: "start"}); }
    });
  });

  // Confirmaciones
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (ev) {
      if (!window.confirm(f.dataset.confirm)) ev.preventDefault();
    });
  });
})();
