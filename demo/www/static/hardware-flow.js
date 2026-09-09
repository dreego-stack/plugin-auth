(() => {
  const status = document.querySelector("#task-status");
  const statusTitle = document.querySelector("#status-title");
  const statusDetail = document.querySelector("#status-detail");
  const next = document.querySelector("#next-step");

  const show = (title, detail, failed = false) => {
    statusTitle.textContent = title;
    statusDetail.textContent = detail;
    status.className = failed ? "task-status failed" : "task-status passed";
    status.focus();
  };
  const complete = (title, detail) => {
    show(title, detail);
    if (next) next.hidden = false;
  };
  const run = async (button, operation) => {
    button.disabled = true;
    show("Working", "Complete the browser or authenticator prompt. This page will announce the result.");
    try {
      await operation();
    } catch (error) {
      show("This step did not complete", `${error.code ?? "ERROR"}: ${error.message}`, true);
    } finally {
      button.disabled = false;
    }
  };

  const support = document.querySelector("#support-status");
  if (support) {
    const ready = window.isSecureContext && window.PublicKeyCredential && navigator.credentials;
    support.textContent = ready
      ? "WebAuthn is available in this browser. You can begin."
      : "WebAuthn is unavailable. Open this page on localhost or HTTPS in Safari, Chrome, Edge, or Firefox.";
    support.className = ready ? "support-ready" : "support-blocked";
  }

  document.querySelector("#register-form")?.addEventListener("submit", event => {
    event.preventDefault();
    const form = event.currentTarget;
    run(event.submitter, async () => {
      const result = await DreegoAuth.register(Object.fromEntries(new FormData(form)));
      complete("Account created successfully", `The server created ${result.user.identifier}. Continue to password login.`);
    });
  });

  document.querySelector("#login-form")?.addEventListener("submit", event => {
    event.preventDefault();
    const form = event.currentTarget;
    run(event.submitter, async () => {
      const result = await DreegoAuth.loginWithPassword(Object.fromEntries(new FormData(form)));
      if (result.secondFactorRequired) throw new Error("This account requires a second factor. Return and create a fresh hardware-test account.");
      complete("Password login successful", `Signed in as ${result.user.identifier}. You may now connect a device passkey.`);
    });
  });

  document.querySelector("#platform-register")?.addEventListener("click", event => run(event.currentTarget, async () => {
    await DreegoAuth.registerPasskey({ attachment: "platform" });
    complete("Device passkey connected", "The server accepted a credential from a built-in platform authenticator.");
  }));

  document.querySelector("#yubikey-register")?.addEventListener("click", event => run(event.currentTarget, async () => {
    await DreegoAuth.registerPasskey({ attachment: "cross-platform" });
    complete("External security key connected", "The server accepted a cross-platform credential. If you selected Security key and touched your YubiKey, its registration succeeded.");
  }));

  document.querySelector("#logout")?.addEventListener("click", event => run(event.currentTarget, async () => {
    await DreegoAuth.logout();
    complete("Signed out successfully", "The server revoked the current session. Continue to test passwordless login.");
  }));

  document.querySelector("#webauthn-login")?.addEventListener("click", event => run(event.currentTarget, async () => {
    const result = await DreegoAuth.loginWithPasskey();
    const response = await fetch("/api/me", { credentials: "same-origin" });
    if (!response.ok) throw new Error(`Login returned, but the protected route responded with HTTP ${response.status}`);
    complete("Passwordless login successful", `Signed in as ${result.user.identifier}. The protected route also accepted this session.`);
  }));
})();
