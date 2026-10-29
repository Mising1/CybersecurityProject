export type Permission =
  | "manage_users" | "manage_settings"
  | "read_content" | "edit_content" | "approve_content";

export type Me = {
  username: string;
  role: string;
  permissions: Permission[];
  must_change_password: boolean;
  idle_timeout_minutes: number;
};

let idleTimer: ReturnType<typeof setTimeout> | undefined;
let idleTimeoutMs = 0;

function resetIdleTimer() {
  if (!idleTimeoutMs) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    location.href = "/login?idle=1";
  }, idleTimeoutMs);
}

export async function api(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
  if (res.status === 401 && path !== "/auth/login") {
    location.href = "/login?idle=1";
    throw new Error("unauthorized");
  }
  resetIdleTimer();
  return res;
}

export async function errorMessage(res: Response): Promise<string> {
  const body = await res.json().catch(() => null);
  return body?.error ?? `Błąd ${res.status}`;
}

export type PasswordPolicy = { min_length: number; passphrase_rule_enabled: boolean };

export async function currentUser(): Promise<Me> {
  const me: Me = await (await api("/auth/me")).json();
  idleTimeoutMs = me.idle_timeout_minutes * 60_000;
  resetIdleTimer();
  if (me.must_change_password && location.pathname !== "/password") {
    location.href = "/password";
    throw new Error("password change required");
  }
  return me;
}

export function renderHeader(me: Me) {
  document.getElementById("who")!.textContent = `${me.username} · ${me.role}`;
  document.getElementById("admin-link")!.hidden = !me.permissions.includes("manage_users");
  document.getElementById("main-nav")!.hidden = me.must_change_password;
  document.getElementById("logout")!.addEventListener("click", logout);
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("pl-PL");
}

export async function logout(): Promise<void> {
  await api("/auth/logout", { method: "POST" });
  location.href = "/login";
}
