(() => {
  const api = globalThis.DreegoAuth ?? {};

  api.basePath = api.basePath ?? "/auth";
  api.configure = ({ basePath = "/auth" } = {}) => {
    api.basePath = basePath.replace(/\/$/, "");
    return api;
  };
  api.csrfToken = () => {
    const cookie = document.cookie.split("; ").find((value) => value.startsWith("csrf_token="));
    return cookie ? decodeURIComponent(cookie.slice("csrf_token=".length)) : "";
  };
  api.headers = () => {
    const headers = { "Content-Type": "application/json", "Accept": "application/json" };
    const token = api.csrfToken();
    if (token) headers["X-CSRF-Token"] = token;
    return headers;
  };
  api.request = async (path, body) => {
    const response = await fetch(`${api.basePath}${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: api.headers(),
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
