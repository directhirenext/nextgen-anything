/**
 * Zero-dependency ES Module SDK client for NextGen-Anything (`nga`) REST endpoints.
 */
export class NgaJsClient {
  constructor(baseUrl = "http://127.0.0.1:8765", timeoutMs = 15000, apiToken = "") {
    this.baseUrl = String(baseUrl || "http://127.0.0.1:8765").trim().replace(/\/+$/, "");
    this.timeoutMs = Math.max(1000, Number(timeoutMs) || 15000);
    this.apiToken = String(apiToken || "").trim();
  }

  _buildHeaders(hasBody) {
    const headers = { Accept: "application/json" };
    if (hasBody) {
      headers["Content-Type"] = "application/json";
    }
    if (this.apiToken) {
      headers["X-NGA-Token"] = this.apiToken;
      headers["Authorization"] = `Bearer ${this.apiToken}`;
    }
    return headers;
  }

  async _request(method, path, payload = null) {
    const cleanPath = String(path || "/").startsWith("/") ? String(path) : `/${path}`;
    const url = `${this.baseUrl}${cleanPath}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const upperMethod = String(method || "GET").toUpperCase();
      const hasBody = payload !== null && upperMethod !== "GET";
      const options = {
        method: upperMethod,
        headers: this._buildHeaders(hasBody),
        signal: controller.signal,
      };
      if (hasBody) {
        options.body = JSON.stringify(payload);
      }

      const resp = await fetch(url, options);
      const text = await resp.text();
      try {
        return JSON.parse(text);
      } catch {
        return {
          ok: false,
          status: resp.status,
          error_code: "NGA_INVALID_RESPONSE",
          message: `Non-JSON response (HTTP ${resp.status})`,
          raw: text.slice(0, 500),
        };
      }
    } catch (err) {
      const isTimeout = Boolean(err && err.name === "AbortError");
      return {
        ok: false,
        error_code: isTimeout ? "NGA_TIMEOUT" : "NGA_NETWORK_UNREACHABLE",
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
      smoke: smokeCode,
    });
  }

  synthesize(findings, appName = "reconstructed_app", outputDir = "synthesized_out", customPrompt = "") {
    return this._request("POST", "/api/synthesize", {
      app_name: appName,
      findings,
      output_dir: outputDir,
      custom_prompt: customPrompt,
    });
  }

  rebuild(kind, target, outputDir = "rebuilt_app", appName = "", customPrompt = "") {
    return this._request("POST", "/api/rebuild", {
      kind,
      target,
      output_dir: outputDir,
      app_name: appName,
      custom_prompt: customPrompt,
    });
  }

  agentTurn(prompt, candidateCode = "", targetLabel = "js_sdk_agent") {
    return this._request("POST", "/api/agent", {
      prompt,
      candidate_code: candidateCode,
      target_label: targetLabel,
    });
  }

  memoryStore(title, body, namespace = "agent_core", tags = []) {
    return this._request("POST", "/api/memory", {
      title,
      body,
      namespace,
      tags,
    });
  }

  memoryRetrieve(query, namespace = "", limit = 5) {
    const qs = new URLSearchParams({ q: String(query || ""), limit: String(limit || 5) });
    if (namespace) qs.set("namespace", String(namespace));
    return this._request("GET", `/api/memory?${qs.toString()}`);
  }

  brief(label, kind = "web", customRequirements = "") {
    return this._request("POST", "/api/brief", {
      label,
      kind,
      custom_requirements: customRequirements,
    });
  }

  ledgerList() {
    return this._request("GET", "/api/ledger");
  }

  ledgerAdd(obligationId, category = "endpoint", title = "", status = "pending") {
    return this._request("POST", "/api/ledger", {
      action: "add",
      obligation_id: obligationId,
      category,
      title: title || obligationId,
      status,
    });
  }

  ledgerUpdate(obligationId, status) {
    return this._request("POST", "/api/ledger", {
      action: "update",
      obligation_id: obligationId,
      status,
    });
  }
        }
