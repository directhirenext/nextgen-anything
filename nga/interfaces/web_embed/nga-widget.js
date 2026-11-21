/**
 * NextGen-Anything (`nga`) Drop-In Website Embed Widget (Zero-Dependency Vanilla JS).
 * Usage:
 *   <div id="nga-widget" data-nga-endpoint="http://127.0.0.1:8765"></div>
 *   <script src="nga-widget.js" defer></script>
 */
(function () {
  "use strict";

  function createNgaWidget(container, options) {
    if (!container) return null;
    const baseUrl = (options && options.endpoint) || container.getAttribute("data-nga-endpoint") || "http://127.0.0.1:8765";
    const cleanBase = baseUrl.replace(/\/+$/, "");

    container.innerHTML = "";
    const wrapper = document.createElement("div");
    wrapper.className = "nga-embed-box";
    wrapper.style.cssText =
      "border:1px solid #30363d;border-radius:10px;padding:14px;background:#161b22;color:#e6edf3;font-family:system-ui,-apple-system,sans-serif;max-width:680px;";

    const title = document.createElement("div");
    title.textContent = "NextGen-Anything (nga) Live Widget";
    title.style.cssText = "font-weight:700;margin-bottom:8px;font-size:15px;";

    const input = document.createElement("textarea");
    input.value = 'print("Hello from nga Website Widget!")';
    input.style.cssText =
      "width:100%;min-height:68px;padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-family:monospace;font-size:12px;box-sizing:border-box;";

    const btnRow = document.createElement("div");
    btnRow.style.cssText = "display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;";

    const simBtn = document.createElement("button");
    simBtn.type = "button";
    simBtn.textContent = "Simulate Code";
    simBtn.style.cssText =
      "padding:7px 12px;border-radius:6px;border:0;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer;";

    const docBtn = document.createElement("button");
    docBtn.type = "button";
    docBtn.textContent = "Check Status";
    docBtn.style.cssText =
      "padding:7px 12px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-weight:600;cursor:pointer;";

    const out = document.createElement("pre");
    out.textContent = "Endpoint: " + cleanBase;
    out.style.cssText =
      "margin-top:10px;padding:10px;border-radius:6px;background:#0d1117;border:1px solid #30363d;font-size:12px;overflow-x:auto;max-height:220px;";

    async function callApi(path, payload) {
      out.textContent = "Running...";
      try {
        const opts = payload
          ? {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            }
          : { method: "GET" };
        const res = await fetch(cleanBase + path, opts);
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
        return data;
      } catch (err) {
        const fallback = {
          ok: false,
          error_code: "NGA_NETWORK_UNREACHABLE",
          message: String(err && err.message ? err.message : err),
          suggested_fix: "Start `nga ui --port 8765` or verify data-nga-endpoint URL.",
        };
        out.textContent = JSON.stringify(fallback, null, 2);
        return fallback;
      }
    }

    simBtn.addEventListener("click", function () {
      callApi("/api/simulate", { label: "widget_snippet", code: input.value });
    });
    docBtn.addEventListener("click", function () {
      callApi("/api/doctor", null);
    });

    btnRow.appendChild(simBtn);
    btnRow.appendChild(docBtn);
    wrapper.appendChild(title);
    wrapper.appendChild(input);
    wrapper.appendChild(btnRow);
    wrapper.appendChild(out);
    container.appendChild(wrapper);

    return {
      simulate: function (code, label) {
        return callApi("/api/simulate", { code: code, label: label || "widget_api" });
      },
      doctor: function () {
        return callApi("/api/doctor", null);
      },
    };
  }

  window.NgaWidget = { mount: createNgaWidget };

  document.addEventListener("DOMContentLoaded", function () {
    const autoNodes = document.querySelectorAll("[data-nga-widget], #nga-widget");
    autoNodes.forEach(function (el) {
      createNgaWidget(el);
    });
  });
})();
        
