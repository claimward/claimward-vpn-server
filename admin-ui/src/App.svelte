<script>
  import { api, getToken, setToken } from './lib/api.js'
  import TenantForm from './lib/TenantForm.svelte'

  let token = $state(getToken())
  let authed = $state(false)
  let tokenInput = $state('')
  let loginError = $state('')

  let overview = $state(null)
  let peers = $state([])
  let tenants = $state([])
  let loadError = $state('')
  let loading = $state(false)

  // Render a timestamp as a short local date-time, '—' if missing/zero.
  function fmtTime(ts) {
    if (!ts) return '—'
    const d = new Date(ts)
    if (isNaN(d) || d.getFullYear() < 2000) return '—'
    return d.toLocaleString()
  }

  // null = none, 'new' = create form, or a tenant object = edit form.
  let editing = $state(null)

  // Active tab: 'peers' | 'tenants' | 'settings'.
  let view = $state('peers')

  // Server settings (invite email). settingsForm is the editable draft.
  let settings = $state(null)
  let settingsForm = $state({ mail_from: '', smtp_addr: '', invite_subject: '', invite_body: '' })
  let settingsMsg = $state('')
  let settingsErr = $state('')
  let savingSettings = $state(false)

  async function refresh() {
    loading = true
    loadError = ''
    try {
      const [ov, ps, ts, set] = await Promise.all([
        api.overview(),
        api.listPeers(),
        api.listTenants(),
        api.getSettings(),
      ])
      overview = ov
      peers = ps
      tenants = ts
      settings = set
      settingsForm = {
        mail_from: set.mail_from ?? '',
        smtp_addr: set.smtp_addr ?? '',
        invite_subject: set.invite_subject ?? '',
        invite_body: set.invite_body ?? '',
      }
      authed = true
    } catch (err) {
      if (err.status === 401) {
        authed = false
        setToken('')
        token = ''
        loginError = 'Invalid token'
      } else {
        loadError = err.message
      }
    } finally {
      loading = false
    }
  }

  async function login(e) {
    e.preventDefault()
    loginError = ''
    setToken(tokenInput.trim())
    token = tokenInput.trim()
    await refresh()
    if (authed) tokenInput = ''
  }

  function logout() {
    setToken('')
    token = ''
    authed = false
    overview = null
    peers = []
    tenants = []
  }

  async function save(t) {
    if (editing === 'new') await api.createTenant(t)
    else await api.updateTenant(editing.id, t)
    editing = null
    await refresh()
  }

  async function saveSettings(e) {
    e.preventDefault()
    settingsMsg = ''
    settingsErr = ''
    savingSettings = true
    try {
      settings = await api.updateSettings(settingsForm)
      settingsMsg = 'Settings saved.'
    } catch (err) {
      settingsErr = err.message
    } finally {
      savingSettings = false
    }
  }

  async function remove(t) {
    if (!confirm(`Delete tenant "${t.name || t.id}"? Connected clients fall back to default.`)) return
    try {
      await api.deleteTenant(t.id)
      await refresh()
    } catch (err) {
      loadError = err.message
    }
  }

  // Auto-load if a token is already stored.
  $effect(() => {
    if (token && !authed) refresh()
  })
</script>

<div class="min-h-screen bg-base-100 text-base-content">
  <header class="navbar bg-base-200 px-6 shadow-sm">
    <div class="flex-1 items-center gap-3">
      <span class="text-xl font-bold tracking-tight">
        <span class="text-primary">claim</span>ward
      </span>
      <span class="badge badge-primary badge-outline badge-sm">admin</span>
    </div>
    {#if authed}
      <div class="flex-none items-center gap-2">
        <button class="btn btn-ghost btn-sm" onclick={refresh} disabled={loading}>
          {#if loading}<span class="loading loading-spinner loading-xs"></span>{/if}
          Refresh
        </button>
        <button
          class="btn btn-ghost btn-sm {view === 'settings' ? 'btn-active text-primary' : ''}"
          onclick={() => (view = 'settings')}
        >
          Settings
        </button>
        <button class="btn btn-ghost btn-sm" onclick={logout}>Sign out</button>
      </div>
    {/if}
  </header>

  {#if !authed}
    <main class="flex items-center justify-center px-6 py-20">
      <form class="card w-full max-w-sm bg-base-200 shadow-xl" onsubmit={login}>
        <div class="card-body gap-4">
          <h2 class="card-title">Admin sign in</h2>
          <p class="text-sm opacity-70">Enter the server's <code>ADMIN_TOKEN</code>.</p>
          {#if loginError}
            <div class="alert alert-error py-2 text-sm">{loginError}</div>
          {/if}
          <input
            class="input input-bordered font-mono"
            type="password"
            placeholder="ADMIN_TOKEN"
            bind:value={tokenInput}
            autocomplete="off"
          />
          <button class="btn btn-primary" type="submit" disabled={loading}>Sign in</button>
        </div>
      </form>
    </main>
  {:else}
    <main class="mx-auto max-w-5xl space-y-8 px-6 py-8">
      <!-- Metrics overview -->
      <section>
        <div class="mb-3 flex items-center justify-between">
          <h2 class="text-lg font-semibold">Overview</h2>
          <a class="link link-secondary text-sm" href="../metrics" target="_blank" rel="noreferrer">
            /metrics →
          </a>
        </div>
        <div class="stats stats-vertical w-full bg-base-200 shadow sm:stats-horizontal">
          <div class="stat">
            <div class="stat-title">Tenants</div>
            <div class="stat-value text-primary">{overview?.tenants ?? '—'}</div>
          </div>
          <div class="stat">
            <div class="stat-title">Active peers</div>
            <div class="stat-value text-success">{overview?.peers ?? '—'}</div>
          </div>
          <div class="stat">
            <div class="stat-title">Route watchers</div>
            <div class="stat-value text-secondary">{overview?.watchers ?? '—'}</div>
          </div>
        </div>
      </section>

      <!-- Tabs -->
      <div role="tablist" class="tabs tabs-bordered">
        <button
          role="tab"
          class="tab {view === 'peers' ? 'tab-active' : ''}"
          onclick={() => (view = 'peers')}
        >
          Active peers
          <span class="badge badge-ghost badge-sm ml-2">{overview?.peers ?? peers.length}</span>
        </button>
        <button
          role="tab"
          class="tab {view === 'tenants' ? 'tab-active' : ''}"
          onclick={() => (view = 'tenants')}
        >
          Tenants & routes
          <span class="badge badge-ghost badge-sm ml-2">{overview?.tenants ?? tenants.length}</span>
        </button>
      </div>

      {#if view === 'peers'}
      <!-- Active peers -->
      <section class="space-y-4">
        <div class="overflow-x-auto rounded-box border border-base-300">
          <table class="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Tenant</th>
                <th>Device</th>
                <th>IP</th>
                <th>Connected</th>
                <th>Lease expiry</th>
              </tr>
            </thead>
            <tbody>
              {#each peers as p (p.ip)}
                <tr class="hover">
                  <td>{p.email || '—'}</td>
                  <td>
                    <span class="badge badge-outline badge-sm">{p.tenant || 'default'}</span>
                  </td>
                  <td>
                    {p.device || '—'}
                    {#if p.os || p.platform}
                      <span class="badge badge-ghost badge-xs ml-1">{[p.os, p.platform].filter(Boolean).join(' · ')}</span>
                    {/if}
                  </td>
                  <td class="font-mono text-sm">{p.ip}</td>
                  <td class="text-sm opacity-80">{fmtTime(p.enrolled_at)}</td>
                  <td class="text-sm opacity-80">{fmtTime(p.lease_expiry)}</td>
                </tr>
              {:else}
                <tr>
                  <td colspan="6" class="py-6 text-center text-sm opacity-60">No active peers.</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
      {/if}

      {#if view === 'tenants'}
      <!-- Tenants -->
      <section class="space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold">Tenants & routes</h2>
          {#if editing === null}
            <button class="btn btn-primary btn-sm" onclick={() => (editing = 'new')}>
              + New tenant
            </button>
          {/if}
        </div>

        {#if loadError}
          <div class="alert alert-error py-2 text-sm">{loadError}</div>
        {/if}

        {#if editing === 'new'}
          <TenantForm onsave={save} oncancel={() => (editing = null)} />
        {/if}

        <div class="overflow-x-auto rounded-box border border-base-300">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Members</th>
                <th>AllowedIPs</th>
                <th>DNS</th>
                <th class="text-right">Serial</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each tenants as t (t.id)}
                {#if editing !== 'new' && editing?.id === t.id}
                  <tr>
                    <td colspan="7" class="p-3">
                      <TenantForm tenant={t} onsave={save} oncancel={() => (editing = null)} />
                    </td>
                  </tr>
                {:else}
                  <tr class="hover">
                    <td class="font-mono text-sm">
                      {t.id}
                      {#if t.id === 'default'}
                        <span class="badge badge-ghost badge-xs ml-1">default</span>
                      {/if}
                    </td>
                    <td>{t.name}</td>
                    <td class="text-sm opacity-80" title={(t.members ?? []).join(', ')}>
                      {(t.members ?? []).length
                        ? `${(t.members ?? []).length} member${(t.members ?? []).length > 1 ? 's' : ''}`
                        : '—'}
                    </td>
                    <td class="font-mono text-xs opacity-80">{(t.allowed_ips ?? []).join(', ') || '—'}</td>
                    <td class="font-mono text-xs opacity-80">{(t.dns ?? []).join(', ') || '—'}</td>
                    <td class="text-right font-mono text-sm">{t.serial}</td>
                    <td class="text-right">
                      <button class="btn btn-ghost btn-xs" onclick={() => (editing = t)}>Edit</button>
                      {#if t.id !== 'default'}
                        <button class="btn btn-ghost btn-xs text-error" onclick={() => remove(t)}>
                          Delete
                        </button>
                      {/if}
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
        <p class="text-xs opacity-60">
          Saving a tenant bumps its serial and pushes the new routes to all connected clients of
          that tenant over gRPC.
        </p>
      </section>
      {/if}

      {#if view === 'settings'}
      <!-- Settings: invitation email -->
      <section class="space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold">Invitation email</h2>
          <span class="badge {settings?.enabled ? 'badge-success' : 'badge-ghost'} badge-outline">
            {settings?.enabled ? 'enabled' : 'disabled'}
          </span>
        </div>

        {#if settingsErr}
          <div class="alert alert-error py-2 text-sm">{settingsErr}</div>
        {/if}
        {#if settingsMsg}
          <div class="alert alert-success py-2 text-sm">{settingsMsg}</div>
        {/if}

        <form class="card bg-base-200 shadow" onsubmit={saveSettings}>
          <div class="card-body gap-4">
            <label class="form-control w-full">
              <span class="label-text mb-1">Sender (From)</span>
              <input
                class="input input-bordered w-full"
                placeholder="Claimward VPN &lt;vpn@example.org&gt;"
                bind:value={settingsForm.mail_from}
              />
              <span class="label-text mt-1 text-xs opacity-60">
                Display name + address, or a bare address. Leave blank to disable invite emails.
              </span>
            </label>

            <label class="form-control w-full">
              <span class="label-text mb-1">SMTP relay (host:port)</span>
              <input
                class="input input-bordered w-full font-mono"
                placeholder="127.0.0.1:25"
                bind:value={settingsForm.smtp_addr}
              />
              <span class="label-text mt-1 text-xs opacity-60">
                Where the server posts mail — typically the local Postfix smarthost.
              </span>
            </label>

            <label class="form-control w-full">
              <span class="label-text mb-1">Subject</span>
              <input
                class="input input-bordered w-full"
                placeholder={"You've been invited to the {{.TenantName}} VPN"}
                bind:value={settingsForm.invite_subject}
              />
            </label>

            <label class="form-control w-full">
              <span class="label-text mb-1">Body</span>
              <textarea
                class="textarea textarea-bordered min-h-40 w-full font-mono text-sm"
                placeholder="Email body…"
                bind:value={settingsForm.invite_body}
              ></textarea>
              <span class="label-text mt-1 text-xs opacity-60">
                Placeholders: <code>{'{{.Email}}'}</code>, <code>{'{{.TenantName}}'}</code>,
                <code>{'{{.TenantID}}'}</code>, <code>{'{{.PortalURL}}'}</code>. Leave subject/body
                blank to use the built-in defaults.
              </span>
            </label>

            <div class="flex items-center gap-3">
              <button class="btn btn-primary" type="submit" disabled={savingSettings}>
                {#if savingSettings}<span class="loading loading-spinner loading-xs"></span>{/if}
                Save settings
              </button>
            </div>
          </div>
        </form>
      </section>
      {/if}
    </main>
  {/if}
</div>
