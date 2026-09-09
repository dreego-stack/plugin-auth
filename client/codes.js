(() => {
  const api = globalThis.DreegoAuth;
  api.requestCode = (input) => api.request("/codes/request", input);
  api.verifyCode = (input) => api.request("/codes/verify", input);
})();
