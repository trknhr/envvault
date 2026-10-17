package admin

import "html/template"

var adminHTML = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EnvVault</title>
  <style>
    :root {
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f7f8fa;
      color: #171a1f;
    }
    * { box-sizing: border-box; }
    body { margin: 0; }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 56px;
      padding: 0 24px;
      border-bottom: 1px solid #d9dde5;
      background: #ffffff;
    }
    h1 { margin: 0; font-size: 18px; font-weight: 650; }
    main {
      display: grid;
      grid-template-columns: minmax(260px, 420px) minmax(320px, 1fr);
      gap: 24px;
      width: min(1180px, calc(100vw - 32px));
      margin: 24px auto;
    }
    section {
      border: 1px solid #d9dde5;
      border-radius: 8px;
      background: #ffffff;
    }
    section h2 {
      margin: 0;
      padding: 14px 16px;
      border-bottom: 1px solid #e6e9ef;
      font-size: 14px;
      font-weight: 650;
    }
    form {
      display: grid;
      gap: 10px;
      padding: 14px 16px 16px;
    }
    label {
      display: grid;
      gap: 4px;
      font-size: 12px;
      font-weight: 600;
      color: #4a5567;
    }
    input, select {
      width: 100%;
      min-height: 34px;
      border: 1px solid #c9cfda;
      border-radius: 6px;
      padding: 7px 9px;
      font: inherit;
      color: #171a1f;
      background: #ffffff;
    }
    button {
      min-height: 34px;
      border: 1px solid #1f6feb;
      border-radius: 6px;
      padding: 7px 10px;
      font: inherit;
      font-weight: 650;
      color: #ffffff;
      background: #1f6feb;
      cursor: pointer;
    }
    button.secondary {
      border-color: #c9cfda;
      color: #171a1f;
      background: #ffffff;
    }
    button.secondary:disabled {
      cursor: default;
      opacity: 0.55;
    }
    .stack { display: grid; gap: 16px; }
    .toolbar {
      display: flex;
      justify-content: flex-end;
      padding: 12px 16px;
      border-bottom: 1px solid #e6e9ef;
    }
    .snippet-output {
      display: grid;
      gap: 8px;
      margin: 0 16px 16px;
      padding: 12px;
      border: 1px solid #d9dde5;
      border-radius: 6px;
      background: #fbfcfd;
    }
    .snippet-output[hidden] { display: none; }
    .snippet-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      color: #4a5567;
      font-size: 12px;
      font-weight: 650;
    }
    pre {
      margin: 0;
      padding: 10px;
      overflow-x: auto;
      border-radius: 6px;
      color: #f7f8fa;
      background: #171a1f;
      font: 12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      white-space: pre;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      font-size: 13px;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid #edf0f5;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: #4a5567;
      font-size: 12px;
      font-weight: 650;
      background: #fbfcfd;
    }
    #status {
      min-width: 160px;
      color: #4a5567;
      font-size: 13px;
      text-align: right;
    }
    @media (max-width: 820px) {
      header { padding: 0 16px; }
      main {
        grid-template-columns: 1fr;
        width: min(100vw - 24px, 680px);
        margin: 16px auto;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>EnvVault</h1>
    <div id="status"></div>
  </header>
  <main>
    <div class="stack">
      <section>
        <h2>Credential</h2>
        <form id="credential-form">
          <label>Name<input name="name" autocomplete="off" placeholder="openai-key/dev"></label>
          <label>Value<input name="value" autocomplete="off" type="password"></label>
          <button type="submit">Add Credential</button>
        </form>
      </section>
      <section>
        <h2>Proxy</h2>
        <form id="proxy-profile-form">
          <label>Name<input name="name" autocomplete="off" placeholder="openai/dev"></label>
          <label>Credential<input name="credential" autocomplete="off" list="credential-options" placeholder="openai-key/dev"></label>
          <label>Provider
            <select name="provider">
              <option value="generic">generic</option>
              <option value="openai-compatible">openai-compatible</option>
            </select>
          </label>
          <label>Target URL<input name="target_url" autocomplete="off" placeholder="https://api.openai.com/v1"></label>
          <label>Allowed Paths<input name="allowed_paths" autocomplete="off" placeholder="/chat/completions"></label>
          <label>Allowed Methods<input name="allowed_methods" autocomplete="off" placeholder="POST"></label>
          <label>Project Binding
            <select name="project_binding">
              <option value="none">none</option>
            </select>
          </label>
          <button type="submit">Add Proxy</button>
        </form>
        <div id="proxy-env-output" class="snippet-output" hidden>
          <div class="snippet-header">
            <span>.env snippet</span>
            <button id="copy-proxy-snippet" class="secondary" type="button" disabled>Copy</button>
          </div>
          <pre id="proxy-env-snippet"></pre>
        </div>
      </section>
      <datalist id="credential-options"></datalist>
    </div>
    <div class="stack">
      <section>
        <h2>Credentials</h2>
        <div class="toolbar"><button id="refresh" class="secondary" type="button">Refresh</button></div>
        <table>
          <thead>
            <tr><th>Name</th><th>Reference</th></tr>
          </thead>
          <tbody id="credentials"></tbody>
        </table>
      </section>
      <section>
        <h2>Proxies</h2>
        <table>
          <thead>
            <tr><th>Name</th><th>Credential</th><th>Target</th><th>.env</th></tr>
          </thead>
          <tbody id="proxies"></tbody>
        </table>
      </section>
    </div>
  </main>
  <script>
    const envvaultToken = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("envvaultAdminToken") || "";
    if (envvaultToken) sessionStorage.setItem("envvaultAdminToken", envvaultToken);
    const statusNode = document.getElementById("status");
    const credentialsNode = document.getElementById("credentials");
    const credentialOptionsNode = document.getElementById("credential-options");
    const proxiesNode = document.getElementById("proxies");
    const proxyEnvOutputNode = document.getElementById("proxy-env-output");
    const proxyEnvSnippetNode = document.getElementById("proxy-env-snippet");
    const copyProxySnippetButton = document.getElementById("copy-proxy-snippet");
    const headers = () => ({
      "Content-Type": "application/json",
      "Authorization": "Bearer " + envvaultToken
    });
    const splitList = (value) => value.split(",").map((item) => item.trim()).filter(Boolean);
    const formatCredentialRef = (credential) => "envvault://" + credential;
    const setStatus = (message) => { statusNode.textContent = message; };
    const request = async (path, options) => {
      const response = await fetch(path, {...options, headers: headers()});
      if (!response.ok) {
        const body = await response.text();
        throw new Error(body || response.statusText);
      }
      return response.json();
    };
    const refreshCredentials = async () => {
      const data = await request("/api/credentials", {method: "GET"});
      credentialsNode.replaceChildren(...data.credentials.map((credential) => {
        const row = document.createElement("tr");
        const nameCell = document.createElement("td");
        nameCell.textContent = credential;
        row.appendChild(nameCell);
        const refCell = document.createElement("td");
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = "Copy ref";
        button.setAttribute("data-credential-ref", formatCredentialRef(credential));
        refCell.appendChild(button);
        row.appendChild(refCell);
        return row;
      }));
      credentialOptionsNode.replaceChildren(...data.credentials.map((credential) => {
        const option = document.createElement("option");
        option.value = credential;
        return option;
      }));
    };
    const refreshProxies = async () => {
      const data = await request("/api/proxies", {method: "GET"});
      proxiesNode.replaceChildren(...data.proxies.map((profile) => {
        const row = document.createElement("tr");
        [profile.name, profile.credential || "", profile.target_url || ""].forEach((value) => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });
        const actionCell = document.createElement("td");
        if (profile.dotenv) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "secondary";
          button.textContent = "Copy .env";
          button.setAttribute("data-dotenv", profile.dotenv);
          actionCell.appendChild(button);
        }
        row.appendChild(actionCell);
        return row;
      }));
    };
    const refreshAll = async () => {
      await Promise.all([refreshCredentials(), refreshProxies()]);
    };
            const showProxySnippet = (dotenv) => {
              proxyEnvSnippetNode.textContent = dotenv || "";
              proxyEnvOutputNode.hidden = !dotenv;
              copyProxySnippetButton.disabled = !dotenv;
            };
            const copyButtonFeedback = (button) => {
              if (!button) return;
              const originalText = button.textContent;
              button.textContent = "Copied";
              button.disabled = true;
              window.setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
              }, 1200);
            };
            const bindForm = (id, path, payload, onSuccess) => {
      document.getElementById(id).addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const data = await request(path, {method: "POST", body: JSON.stringify(payload(new FormData(event.currentTarget)))});
          event.currentTarget.reset();
          await refreshAll();
          if (onSuccess) onSuccess(data);
          setStatus("Saved");
        } catch (error) {
          setStatus("Error");
        }
      });
    };
    bindForm("credential-form", "/api/credentials", (form) => ({
      name: form.get("name"),
      value: form.get("value")
    }));
    bindForm("proxy-profile-form", "/api/proxies", (form) => ({
      name: form.get("name"),
      credential: form.get("credential"),
      provider: form.get("provider"),
      target_url: form.get("target_url"),
      allowed_paths: splitList(form.get("allowed_paths") || ""),
      allowed_methods: splitList(form.get("allowed_methods") || "POST"),
      project_binding: form.get("project_binding")
    }), (data) => showProxySnippet(data.dotenv));
            const copyDotenv = async (text, button) => {
              if (!text) return;
              showProxySnippet(text);
              await navigator.clipboard.writeText(text);
              copyButtonFeedback(button);
              setStatus("Copied");
            };
            copyProxySnippetButton.addEventListener("click", async () => {
              await copyDotenv(proxyEnvSnippetNode.textContent, copyProxySnippetButton);
            });
            proxiesNode.addEventListener("click", async (event) => {
              const button = event.target.closest("button[data-dotenv]");
              if (!button) return;
              await copyDotenv(button.getAttribute("data-dotenv") || "", button);
            });
            credentialsNode.addEventListener("click", async (event) => {
              const button = event.target.closest("button[data-credential-ref]");
              if (!button) return;
              await navigator.clipboard.writeText(button.getAttribute("data-credential-ref") || "");
              copyButtonFeedback(button);
              setStatus("Copied");
            });
    document.getElementById("refresh").addEventListener("click", () => refreshAll().catch(() => setStatus("Error")));
    refreshAll().catch(() => setStatus("Locked"));
  </script>
</body>
</html>`))
