import { createHmac } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const demoDir = resolve(import.meta.dir, "..");
const artifactDir = resolve(process.env.E2E_ARTIFACT_DIR || ".tmp/e2e");
const databasePath = resolve(artifactDir, "auth.json");
const origin = process.env.E2E_ORIGIN || "http://localhost:18081";
const results: { passed: string[]; console: string[]; responses: { status: number; url: string }[] } = {
  passed: [], console: [], responses: [],
};

await rm(artifactDir, { recursive: true, force: true });
await mkdir(artifactDir, { recursive: true });

const go = process.env.GO_BINARY || "go";
const executable = resolve(artifactDir, "demo-server");
const build = Bun.spawnSync([go, "build", "-o", executable, "."], { cwd: demoDir, stderr: "pipe" });
if (!build.success) throw new Error(`build demo: ${build.stderr.toString()}`);

const server = Bun.spawn([executable], {
  cwd: demoDir,
  env: {
    ...process.env,
    AUTH_SECRET: "0707070707070707070707070707070707070707070707070707070707070707",
    AUTH_DB: databasePath,
    AUTH_ORIGIN: origin,
    PORT: new URL(origin).port,
  },
  stdout: "pipe",
  stderr: "pipe",
});
const stdout = new Response(server.stdout).text();
const stderr = new Response(server.stderr).text();

try {
  await waitForServer();
  await runBrowserTest();
  await verifyDatabase();
} catch (error) {
  await writeFile(resolve(artifactDir, "failure.txt"), String(error));
  throw error;
} finally {
  server.kill();
  await server.exited;
  await writeFile(resolve(artifactDir, "server.log"), (await stdout) + (await stderr));
  await writeFile(resolve(artifactDir, "results.json"), JSON.stringify(results, null, 2));
}

async function runBrowserTest() {
  const view = new Bun.WebView({
    width: 1280,
    height: 900,
    backend: { type: "chrome", url: false, argv: ["--no-sandbox"] },
    console: (type, ...args) => results.console.push(`${type}: ${args.join(" ")}`),
  });
  try {
    await view.navigate("about:blank");
    await view.cdp("Network.enable");
    view.addEventListener("Network.responseReceived", (event: Event) => {
      const response = (event as Event & { data: { response: { status: number; url: string } } }).data.response;
      if (response.url.startsWith(origin)) results.responses.push({ status: response.status, url: response.url });
    });
    await view.navigate(origin);
    assert(await view.evaluate("document.compatMode === 'CSS1Compat'"), "page uses standards mode");
    assert(await view.evaluate("document.querySelector('link[rel=icon]')?.getAttribute('href') === '/favicon.svg'"), "favicon is linked");

    const email = `browser-${Date.now()}@example.com`;
    const password = "correct horse battery staple";
    await fill(view, "#register-form input[name=identifier]", email);
    await fill(view, "#register-form input[name=displayName]", "Browser Test");
    await fill(view, "#register-form input[name=password]", password);
    await click(view, "#register-form button[type=submit]");
    await waitForText(view, "#toast", "Account created");
    assert(await view.evaluate("document.querySelector('#register-form input[name=identifier]').value === ''"), "registration form resets after await");

    await fill(view, "#login-form input[name=identifier]", email);
    await fill(view, "#login-form input[name=password]", password);
    await click(view, "#login-form button[type=submit]");
    await waitForText(view, "#toast", "Signed in");
    assert(await view.evaluate("fetch('/api/me').then(response => response.status === 200)"), "protected route accepts session");

    await click(view, "#totp-setup");
    await waitForText(view, "#toast", "Add the secret");
    const secretText = String(await view.evaluate("document.querySelector('#totp-secret').textContent"));
    const secret = secretText.match(/^Secret: ([A-Z2-7]+)/)?.[1];
    assert(secret, "TOTP secret is displayed");
    await fill(view, "#totp-form input[name=code]", totp(secret));
    await click(view, "#totp-form button[type=submit]");
    await waitForText(view, "#toast", "TOTP enabled");
    const recoveryCode = String(await view.evaluate("document.querySelector('#recovery-codes').textContent.trim().split('\\n')[0]"));
    assert(recoveryCode.length > 0, "recovery codes are displayed");

    await click(view, "#logout");
    await waitForText(view, "#toast", "Signed out");
    await passwordLogin(view, email, password, "Enter your TOTP");
    assert(await view.evaluate("fetch('/api/me').then(response => response.status === 401)"), "MFA gate blocks partial session");
    await fill(view, "#totp-login-form input[name=code]", totp(secret));
    await click(view, "#totp-login-form button[type=submit]");
    await waitForText(view, "#toast", "Second factor accepted");
    assert(await view.evaluate("document.querySelector('#totp-login-form input[name=code]').value === ''"), "TOTP form resets after await");

    await click(view, "#logout");
    await waitForText(view, "#toast", "Signed out");
    await passwordLogin(view, email, password, "Enter your TOTP");
    await fill(view, "#recovery-login-form input[name=code]", recoveryCode);
    await click(view, "#recovery-login-form button[type=submit]");
    await waitForText(view, "#toast", "Recovery code consumed");
    assert(await view.evaluate("document.querySelector('#recovery-login-form input[name=code]').value === ''"), "recovery form resets after await");

    await view.resize(320, 800);
    assert(await view.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), "320px viewport has no horizontal overflow");
    for (const path of [
      "/hardware-keys", "/hardware-keys/register", "/hardware-keys/login",
      "/hardware-keys/connect-passkey", "/hardware-keys/logout-passkey", "/hardware-keys/verify-passkey",
      "/hardware-keys/connect-yubikey", "/hardware-keys/logout-yubikey", "/hardware-keys/verify-yubikey",
    ]) {
      await view.navigate(origin + path);
      assert(await view.evaluate("Boolean(document.querySelector('main.task-page h1'))"), `hardware step renders at ${path}`);
    }
    assert(results.console.every(line => !line.startsWith("error:")), "browser console has no errors");
    assert(results.responses.every(response => response.status < 500), "browser received no server errors");
    await Bun.write(resolve(artifactDir, "final.png"), await view.screenshot());
  } finally {
    view.close();
  }
}

async function passwordLogin(view: Bun.WebView, email: string, password: string, expected: string) {
  await fill(view, "#login-form input[name=identifier]", email);
  await fill(view, "#login-form input[name=password]", password);
  const valid = await view.evaluate(`(() => {
    const form = document.querySelector('#login-form');
    return form.checkValidity() && form.identifier.value === ${JSON.stringify(email)} && form.password.value === ${JSON.stringify(password)};
  })()`);
  assert(valid, "password login form contains valid values");
  await click(view, "#login-form button[type=submit]");
  await waitForText(view, "#toast", expected);
}

async function fill(view: Bun.WebView, selector: string, value: string) {
  await view.scrollTo(selector, { block: "center" });
  await view.evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(selector)});
    input.value = '';
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await view.click(selector);
  await view.type(value);
}

async function click(view: Bun.WebView, selector: string) {
  await view.scrollTo(selector, { block: "center" });
  await view.click(selector);
}

async function waitForText(view: Bun.WebView, selector: string, text: string) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await view.evaluate(`document.querySelector(${JSON.stringify(selector)})?.textContent.includes(${JSON.stringify(text)})`)) return;
    await Bun.sleep(50);
  }
  throw new Error(`timeout waiting for ${JSON.stringify(text)} in ${selector}`);
}

async function waitForServer() {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      if ((await fetch(origin)).ok) return;
    } catch {}
    await Bun.sleep(100);
  }
  throw new Error(`demo did not start at ${origin}`);
}

async function verifyDatabase() {
  const state = JSON.parse(await readFile(databasePath, "utf8"));
  assert(Object.keys(state.users).length === 1, "database contains one user");
  assert(Object.keys(state.passwords).length === 1, "database contains one password credential");
  assert(Object.keys(state.totp).length === 1, "database contains one TOTP credential");
  const recovery = Object.values(state.recovery)[0] as { UsedAt: string }[];
  assert(recovery.length === 10 && recovery.filter(code => code.UsedAt !== "0001-01-01T00:00:00Z").length === 1, "one of ten recovery codes is consumed");
  assert(Object.keys(state.sessions).length === 1, "database contains the active MFA session");
}

function totp(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of secret) bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map(byte => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
  results.passed.push(message);
  console.log(`PASS ${message}`);
}
