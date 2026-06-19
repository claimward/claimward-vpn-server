<script>
  // Editor for a single tenant. `tenant` null => create mode.
  let { tenant = null, onsave, oncancel } = $props()

  const isNew = $derived(tenant === null)

  let id = $state(tenant?.id ?? '')
  let name = $state(tenant?.name ?? '')
  let members = $state([...(tenant?.members ?? [])])
  let inviteEmail = $state('')
  let domains = $state((tenant?.domains ?? []).join(', '))
  let allowedIps = $state((tenant?.allowed_ips ?? []).join(', '))
  let dns = $state((tenant?.dns ?? []).join(', '))
  let saving = $state(false)
  let error = $state('')

  const list = (s) =>
    s.split(',').map((x) => x.trim()).filter(Boolean)

  // Invite a user by adding their email to the member list (case-insensitive,
  // deduped). Persisted when the tenant is saved.
  function invite() {
    const email = inviteEmail.trim().toLowerCase()
    if (!email) return
    if (!email.includes('@')) {
      error = 'Enter a valid email address.'
      return
    }
    if (!members.some((m) => m.toLowerCase() === email)) {
      members = [...members, email]
    }
    inviteEmail = ''
    error = ''
  }

  function removeMember(email) {
    members = members.filter((m) => m !== email)
  }

  function onInviteKeydown(e) {
    if (e.key === 'Enter') {
      e.preventDefault()
      invite()
    }
  }

  async function submit(e) {
    e.preventDefault()
    saving = true
    error = ''
    try {
      await onsave({
        id: id.trim(),
        name: name.trim(),
        members,
        domains: list(domains),
        allowed_ips: list(allowedIps),
        dns: list(dns),
      })
    } catch (err) {
      error = err.message
    } finally {
      saving = false
    }
  }
</script>

<form class="card bg-base-200 shadow-md" onsubmit={submit}>
  <div class="card-body gap-3">
    <h3 class="card-title text-base">
      {isNew ? 'New tenant' : `Edit ${tenant.name || tenant.id}`}
      {#if !isNew}
        <span class="badge badge-ghost badge-sm font-mono">serial {tenant.serial}</span>
      {/if}
    </h3>

    {#if error}
      <div class="alert alert-error py-2 text-sm">{error}</div>
    {/if}

    <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
      <label class="form-control">
        <span class="label-text mb-1 text-xs opacity-70">Tenant ID</span>
        <input
          class="input input-bordered input-sm font-mono"
          bind:value={id}
          placeholder="acme (auto from name if blank)"
          disabled={!isNew}
        />
      </label>
      <label class="form-control">
        <span class="label-text mb-1 text-xs opacity-70">Display name</span>
        <input class="input input-bordered input-sm" bind:value={name} placeholder="Acme Corp" />
      </label>
    </div>

    <div class="form-control">
      <span class="label-text mb-1 text-xs opacity-70">
        Members — invite users by email (only members may connect to this tenant)
      </span>
      <div class="flex gap-2">
        <input
          class="input input-bordered input-sm font-mono flex-1"
          bind:value={inviteEmail}
          onkeydown={onInviteKeydown}
          type="email"
          placeholder="user@acme.com"
        />
        <button type="button" class="btn btn-secondary btn-sm" onclick={invite}>Invite</button>
      </div>
      {#if members.length}
        <div class="mt-2 flex flex-wrap gap-2">
          {#each members as m (m)}
            <span class="badge badge-outline gap-1">
              {m}
              <button
                type="button"
                class="text-error"
                aria-label="Remove {m}"
                onclick={() => removeMember(m)}
              >✕</button>
            </span>
          {/each}
        </div>
      {:else}
        <p class="mt-1 text-xs opacity-60">No members yet — nobody can connect to this tenant.</p>
      {/if}
    </div>

    <label class="form-control">
      <span class="label-text mb-1 text-xs opacity-70">Email domains (comma-separated, legacy — no longer grants access)</span>
      <input
        class="input input-bordered input-sm font-mono"
        bind:value={domains}
        placeholder="acme.com, acme.io"
      />
    </label>

    <label class="form-control">
      <span class="label-text mb-1 text-xs opacity-70">Pushed routes / AllowedIPs (comma-separated CIDRs)</span>
      <input
        class="input input-bordered input-sm font-mono"
        bind:value={allowedIps}
        placeholder="10.80.0.0/24, 10.0.0.0/8"
      />
    </label>

    <label class="form-control">
      <span class="label-text mb-1 text-xs opacity-70">DNS servers (comma-separated)</span>
      <input
        class="input input-bordered input-sm font-mono"
        bind:value={dns}
        placeholder="10.80.0.1"
      />
    </label>

    <div class="card-actions mt-1 justify-end">
      <button type="button" class="btn btn-ghost btn-sm" onclick={oncancel}>Cancel</button>
      <button type="submit" class="btn btn-primary btn-sm" disabled={saving}>
        {#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}
        {isNew ? 'Create' : 'Save & push'}
      </button>
    </div>
  </div>
</form>
