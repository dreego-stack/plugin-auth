(() => {
  const api = globalThis.DreegoAuth;
  api.register = (input) => api.request("/register", input);
  api.loginWithPassword = (input) => api.request("/login/password", input);
  api.logout = () => api.request("/logout");
})();
