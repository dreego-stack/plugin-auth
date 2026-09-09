(() => {
  const api = globalThis.DreegoAuth;
  const decode = (value) => {
    const input = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(input.padEnd(Math.ceil(input.length / 4) * 4, "="));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };
  const encode = (value) => {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const creationOptions = (value) => ({
    ...value,
    challenge: decode(value.challenge),
    user: { ...value.user, id: decode(value.user.id) },
    excludeCredentials: (value.excludeCredentials ?? []).map((item) => ({ ...item, id: decode(item.id) })),
  });
  const requestOptions = (value) => ({
    ...value,
    challenge: decode(value.challenge),
    allowCredentials: (value.allowCredentials ?? []).map((item) => ({ ...item, id: decode(item.id) })),
  });
  const serialize = (credential) => {
    const response = credential.response;
    const result = {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: encode(response.clientDataJSON) },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment,
    };
    if (response.attestationObject) {
      result.response.attestationObject = encode(response.attestationObject);
      result.response.transports = response.getTransports?.() ?? [];
    } else {
      result.response.authenticatorData = encode(response.authenticatorData);
      result.response.signature = encode(response.signature);
      result.response.userHandle = response.userHandle ? encode(response.userHandle) : null;
    }
    return result;
  };
  const finish = async (path, challengeId, credential) => {
    const response = await fetch(`${api.basePath}${path}?challenge=${encodeURIComponent(challengeId)}`, {
      method: "POST",
      credentials: "same-origin",
      headers: api.headers(),
      body: JSON.stringify(serialize(credential)),
    });
    const payload = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) {
      const error = new Error(payload?.error?.message ?? "Passkey request failed");
      error.code = payload?.error?.code ?? "PASSKEY_FAILED";
      error.status = response.status;
      throw error;
    }
    return payload;
  };
  api.registerPasskey = async ({ attachment = "" } = {}) => {
	const begin = await api.request("/passkeys/register/begin", { attachment });
    const credential = await navigator.credentials.create({ publicKey: creationOptions(begin.options.publicKey) });
    return finish("/passkeys/register/finish", begin.challengeId, credential);
  };
  api.loginWithPasskey = async () => {
    const begin = await api.request("/login/passkey/begin");
    const credential = await navigator.credentials.get({ publicKey: requestOptions(begin.options.publicKey) });
    return finish("/login/passkey/finish", begin.challengeId, credential);
  };
})();
