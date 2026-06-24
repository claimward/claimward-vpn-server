// Thin client for the admin API. The ADMIN_TOKEN is held client-side (the SPA
// itself is served unauthenticated) and presented as a bearer on every call.
const TOKEN_KEY = 'claimward.admin.token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

async function req(method, path, body) {
  const res = await fetch(`./api${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (res.status === 204) return null
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`)
    err.status = res.status
    throw err
  }
  return data
}

export const api = {
  overview: () => req('GET', '/overview'),
  listPeers: () => req('GET', '/peers'),
  listTenants: () => req('GET', '/tenants'),
  createTenant: (t) => req('POST', '/tenants', t),
  updateTenant: (id, t) => req('PUT', `/tenants/${encodeURIComponent(id)}`, t),
  deleteTenant: (id) => req('DELETE', `/tenants/${encodeURIComponent(id)}`),
  getSettings: () => req('GET', '/settings'),
  updateSettings: (s) => req('PUT', '/settings', s),
}
