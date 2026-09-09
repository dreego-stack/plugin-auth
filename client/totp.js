(() => {
  const api = globalThis.DreegoAuth;
  api.setupTOTP = () => api.request("/totp/setup");
  api.confirmTOTP = (code) => api.request("/totp/confirm", { code });
  api.loginWithTOTP = (code) => api.request("/login/totp", { code });
  api.loginWithRecoveryCode = (code) => api.request("/login/recovery", { code });
})();
