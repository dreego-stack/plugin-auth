(() => {
  const api = globalThis.DreegoAuth ?? {};

  api.basePath = api.basePath ?? "/auth";
  api.configure = ({ basePath = "/auth" } = {}) => {
    api.basePath = basePath.replace(/\/$/, "");
    return api;
  };
  api.request = async (path, body) => {
    const response = await fetch(`${api.basePath}${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const payload = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) {
      const error = new Error(payload?.error?.message ?? "Authentication request failed");
      error.code = payload?.error?.code ?? "AUTH_REQUEST_FAILED";
      error.status = response.status;
      throw error;
    }
    return payload;
  };

  globalThis.DreegoAuth = api;
})();
