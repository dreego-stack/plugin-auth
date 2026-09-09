(() => {
  const toast = document.querySelector("#toast");
  const sessionLabel = document.querySelector("#session-label");
  const sessionDetail = document.querySelector("#session-detail");
  let toastTimer;

  const notify = (message, error = false) => {
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.className = error ? "visible error" : "visible";
    toastTimer = setTimeout(() => { toast.className = ""; }, 4500);
  };
  const busy = async (button, operation) => {
    button.disabled = true;
    try { return await operation(); }
    catch (error) { notify(`${error.code ?? "ERROR"}: ${error.message}`, true); throw error; }
    finally { button.disabled = false; }
  };
  const signedIn = (user, method) => {
    sessionLabel.textContent = user.displayName || user.identifier;
    sessionDetail.textContent = `Signed in using ${method}.`;
  };

  document.querySelector("#register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    await busy(event.submitter, async () => {
      const result = await DreegoAuth.register(values);
      notify(`Account created for ${result.user.identifier}. Sign in to continue.`);
      event.currentTarget.reset();
    }).catch(() => {});
  });

  document.querySelector("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    await busy(event.submitter, async () => {
      const result = await DreegoAuth.loginWithPassword(values);
      signedIn(result.user, result.secondFactorRequired ? "password; second factor required" : "password");
      notify(result.secondFactorRequired ? "Enter your TOTP or recovery code to finish." : "Signed in.");
    }).catch(() => {});
  });

  for (const button of document.querySelectorAll("[data-passkey-register]")) {
    button.addEventListener("click", () => busy(button, async () => {
      await DreegoAuth.registerPasskey({ attachment: button.dataset.passkeyRegister });
      notify("Credential registered.");
    }).catch(() => {}));
  }
  document.querySelector("#passkey-login").addEventListener("click", (event) => busy(event.currentTarget, async () => {
    const result = await DreegoAuth.loginWithPasskey();
    signedIn(result.user, "WebAuthn");
    notify("Signed in with WebAuthn.");
  }).catch(() => {}));

  document.querySelector("#totp-setup").addEventListener("click", (event) => busy(event.currentTarget, async () => {
    const result = await DreegoAuth.setupTOTP();
    document.querySelector("#totp-secret").textContent = `Secret: ${result.secret}\n${result.uri}`;
    notify("Add the secret to an authenticator app, then confirm a code.");
  }).catch(() => {}));
  document.querySelector("#totp-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = new FormData(event.currentTarget).get("code");
    await busy(event.submitter, async () => {
      const result = await DreegoAuth.confirmTOTP(code);
      document.querySelector("#recovery-codes").textContent = result.recoveryCodes.join("\n");
      notify("TOTP enabled. Save these recovery codes now.");
    }).catch(() => {});
  });
})();
