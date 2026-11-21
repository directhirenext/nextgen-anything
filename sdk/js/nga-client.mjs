/**
 * Zero-dependency ES Module SDK client for NextGen-Anything (`nga`) REST endpoints.
 */
export class NgaJsClient {
  constructor(baseUrl = "http://127.0.0.1:8765", timeoutMs = 15000) {
    this.baseUrl = String(baseUrl || "http://127.0.0.1:8765").replace(/\/+$/, "");
    this.timeoutMs = Math.max(1000, Number(timeoutMs) || 15000);
  }

  async _request(method, path, payload = null) {
    const cleanPath = path.startsWith("/") ? path : `/${path}`;
    const url = `${this.baseUrl}${cleanPath}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const options = {
        method: String(method || "GET").toUpperCase(),
        headers: { Accept: "application/json" },
        signal: controller.signal,
      };
      if (payload !== null && options.method !== "GET") {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(payload);
      }

      const resp = await fetch(url, options);
      const text = await resp.text();
      try {
        return JSON.parse(text);
      } catch {
        return {
          ok: resp.ok,
          status: resp.status,
          raw: text,
        };
      }
    } catch (err) {
      return {
        ok: false,
        error_code: "NGA_NETWORK_UNREACHABLE",
        message: String(err && err.message ? err.message : err),
        recoverable: true,
        suggested_fix: "Start `nga ui --port 8765` and verify baseUrl.",
      };
    } finally {
      clearTimeout(timer);
    }
  }

  doctor() {
    return this._request("GET", "/api/doctor");
  }

  inspect(kind, target) {
    return this._request("POST", "/api/inspect", { kind, target });
  }

  simulatePython(code, label = "js_sdk_snippet", smokeCode = "") {
    return this._request("POST", "/api/simulate", {
      code,
      label,
      smoke_code: smokeCode,
    });
  }

  brief(label, kind = "web") {
    return this._request("POST", "/api/brief", { label, kind });
  }

  ledgerList() {
    return this._request("GET", "/api/ledger");
  }
    }
          
