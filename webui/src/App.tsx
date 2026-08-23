import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, ACLRule, AuditEntry, Device, SetupKey, ServerStatus, User } from './api'

type Auth = 'checking' | 'login' | 'ready'

export default function App() {
  const [auth, setAuth] = useState<Auth>('checking')
  const [server, setServer] = useState<ServerStatus | null>(null)

  useEffect(() => {
    api
      .status()
      .then((s) => {
        setServer(s)
        setAuth('ready')
      })
      .catch(() => setAuth('login'))
  }, [])

  if (auth === 'checking') return <div className="center muted">loading…</div>
  if (auth === 'login')
    return (
      <Login
        onSuccess={async () => {
          setServer(await api.status())
          setAuth('ready')
        }}
      />
    )
  return (
    <Dashboard
      server={server!}
      onLogout={async () => {
        await api.logout()
        setAuth('login')
      }}
    />
  )
}

function Login({ onSuccess }: { onSuccess: () => Promise<void> }) {
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [signupOn, setSignupOn] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.authInfo().then((i) => setSignupOn(i.signup_enabled)).catch(() => {})
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (mode === 'signup') await api.signup(username, password)
      else await api.login(username || 'admin', password)
      await onSuccess()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : `${mode} failed`)
      setBusy(false)
    }
  }

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <Logo />
        <p className="muted">{mode === 'signup' ? 'Create your account' : 'Sign in to manage your mesh'}</p>
        <input
          type="text"
          placeholder={mode === 'signup' ? 'choose a username' : 'username (admin)'}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder={mode === 'signup' ? 'choose a password (8+ chars)' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <div className="error">{error}</div>}
        <button disabled={busy || !password || (mode === 'signup' && !username)}>
          {busy ? '…' : mode === 'signup' ? 'create account' : 'sign in'}
        </button>
        {signupOn && (
          <button
            type="button"
            className="ghost"
            onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setError('') }}
          >
            {mode === 'login' ? 'new here? create an account' : 'back to sign in'}
          </button>
        )}
      </form>
    </div>
  )
}

function Dashboard({ server, onLogout }: { server: ServerStatus; onLogout: () => void }) {
  const [devices, setDevices] = useState<Device[]>([])
  const [keys, setKeys] = useState<SetupKey[]>([])
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [d, k] = await Promise.all([api.devices(), api.setupKeys()])
      setDevices(d)
      setKeys(k)
      setError('')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) location.reload()
      else setError('cannot reach server')
    }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [refresh])

  const admin = server.role === 'admin'
  return (
    <div className="page">
      <header>
        <Logo />
        <div className="net muted">
          network <b>{server.network}</b> · {server.v4_prefix}
          {server.dns_domain && <> · dns <b>{server.dns_domain}</b></>}
        </div>
        <div className="spacer" />
        <span className="muted">
          {server.username} <span className="pill offline">{server.role}</span>
        </span>
        <span className="muted version">{server.version}</span>
        <button className="ghost" onClick={onLogout}>
          log out
        </button>
      </header>
      {error && <div className="error banner">{error}</div>}
      <Devices devices={devices} onChanged={refresh} admin={admin} />
      {admin && <AccessRules devices={devices} />}
      <SetupKeys keys={keys} onChanged={refresh} admin={admin} />
      {admin && <Users signupEnabled={server.signup_enabled} />}
      {admin && <Audit />}
      <footer className="muted">
        Join a device: <code>overmesh up -server &lt;this-host&gt;:41641 -key sk-…</code>
      </footer>
    </div>
  )
}

function Devices({ devices, onChanged, admin }: { devices: Device[]; onChanged: () => void; admin: boolean }) {
  const remove = async (d: Device) => {
    if (!confirm(`Remove ${d.hostname} from the mesh? It will lose connectivity immediately.`)) return
    await api.deleteDevice(d.id)
    onChanged()
  }

  const toggleRoute = async (d: Device, route: string, approved: boolean) => {
    if (
      approved &&
      (route === '0.0.0.0/0' || route === '::/0') &&
      !confirm(`Approve ${d.hostname} as an EXIT NODE? Devices that select it will send all their internet traffic through it.`)
    )
      return
    await api.setRouteApproval(d.id, route, approved)
    onChanged()
  }

  const anyRoutes = devices.some((d) => (d.routes?.length ?? 0) > 0)
  const anyOwners = admin && devices.some((d) => d.owner && d.owner !== 'admin')

  return (
    <section className="card">
      <h2>
        Devices <span className="count">{devices.length}</span>
      </h2>
      {devices.length === 0 ? (
        <p className="muted">No devices yet — create a setup key below and run <code>overmesh up</code>.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>name</th>
              <th>overlay IPv4</th>
              <th>overlay IPv6</th>
              <th>os</th>
              {anyOwners && <th>owner</th>}
              {anyRoutes && <th>routes</th>}
              <th>state</th>
              <th>last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td className="name">{d.hostname}</td>
                <td>
                  <code>{d.ipv4}</code>
                </td>
                <td>
                  <code>{d.ipv6}</code>
                </td>
                <td>{d.os}</td>
                {anyOwners && <td className="muted">{d.owner}</td>}
                {anyRoutes && (
                  <td>
                    <div className="chips">
                      {(d.routes ?? []).map((r) => {
                        const isExit = r.route === '0.0.0.0/0' || r.route === '::/0'
                        return (
                          <button
                            key={r.route}
                            className={r.approved ? 'chip on' : 'chip'}
                            disabled={!admin}
                            title={
                              admin
                                ? (r.approved ? 'Approved — click to revoke' : 'Awaiting approval — click to approve') +
                                  (isExit ? ' (exit node)' : '')
                                : 'Only admins approve routes'
                            }
                            onClick={() => admin && toggleRoute(d, r.route, !r.approved)}
                          >
                            {isExit ? `exit node (${r.route})` : r.route}
                            {r.approved ? ' ✓' : ' ?'}
                          </button>
                        )
                      })}
                    </div>
                  </td>
                )}
                <td>
                  <span className={d.online ? 'pill online' : 'pill offline'}>
                    {d.online ? 'online' : 'offline'}
                  </span>
                </td>
                <td className="muted">{d.online ? 'now' : ago(d.last_seen)}</td>
                <td>
                  <button className="ghost danger" onClick={() => remove(d)}>
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function SetupKeys({ keys, onChanged, admin }: { keys: SetupKey[]; onChanged: () => void; admin: boolean }) {
  const [reusable, setReusable] = useState(true)
  const [expires, setExpires] = useState(0)
  const [creating, setCreating] = useState(false)

  const create = async () => {
    setCreating(true)
    try {
      await api.createSetupKey(reusable, expires)
      onChanged()
    } finally {
      setCreating(false)
    }
  }

  const active = keys.filter((k) => !k.revoked && !k.expired)
  const inactive = keys.filter((k) => k.revoked || k.expired)

  return (
    <section className="card">
      <h2>
        Setup keys <span className="count">{active.length}</span>
      </h2>
      <div className="keybar">
        <label>
          <input type="checkbox" checked={reusable} onChange={(e) => setReusable(e.target.checked)} />
          reusable
        </label>
        <select value={expires} onChange={(e) => setExpires(Number(e.target.value))}>
          <option value={0}>never expires</option>
          <option value={1}>expires in 1 hour</option>
          <option value={24}>expires in 1 day</option>
          <option value={168}>expires in 1 week</option>
        </select>
        <button onClick={create} disabled={creating}>
          {creating ? 'creating…' : '+ new setup key'}
        </button>
      </div>
      {keys.length === 0 && <p className="muted">No setup keys yet.</p>}
      {[...active, ...inactive].map((k) => (
        <KeyRow key={k.id} k={k} onChanged={onChanged} admin={admin} />
      ))}
    </section>
  )
}

function KeyRow({ k, onChanged, admin }: { k: SetupKey; onChanged: () => void; admin: boolean }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number>(0)
  const dead = k.revoked || k.expired

  const copy = async () => {
    await navigator.clipboard.writeText(k.key)
    setCopied(true)
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className={dead ? 'keyrow dead' : 'keyrow'}>
      <code className="key">{k.key}</code>
      <span className="muted tags">
        {admin && k.owner && k.owner !== 'admin' && `${k.owner} · `}
        {k.reusable ? 'reusable' : 'single-use'}
        {k.used_count > 0 && ` · used ${k.used_count}×`}
        {k.expires_at > 0 && !k.expired && ` · expires ${ago(k.expires_at)}`}
        {k.expired && ' · expired'}
        {k.revoked && ' · revoked'}
      </span>
      <div className="spacer" />
      {!dead && (
        <>
          <button className="ghost" onClick={copy}>
            {copied ? 'copied ✓' : 'copy'}
          </button>
          <button
            className="ghost danger"
            onClick={async () => {
              await api.revokeSetupKey(k.id)
              onChanged()
            }}
          >
            revoke
          </button>
        </>
      )}
    </div>
  )
}

// AccessRules is the visual ACL editor: the database is the source of
// truth and this UI is the only editor — no config files.
function AccessRules({ devices }: { devices: Device[] }) {
  const [rules, setRules] = useState<ACLRule[]>([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    api.acl().then((r) => setRules(r.rules ?? [])).catch(() => {})
  }, [])

  const mutate = (fn: (r: ACLRule[]) => ACLRule[]) => {
    setRules(fn)
    setDirty(true)
  }
  const update = (i: number, patch: Partial<ACLRule>) =>
    mutate((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const move = (i: number, d: number) =>
    mutate((rs) => {
      const j = i + d
      if (j < 0 || j >= rs.length) return rs
      const copy = [...rs]
      ;[copy[i], copy[j]] = [copy[j], copy[i]]
      return copy
    })

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      await api.setACL(rules)
      setDirty(false)
      const fresh = await api.acl()
      setRules(fresh.rules ?? [])
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'save failed')
    } finally {
      setSaving(false)
    }
  }

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(rules, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'overmesh-access-rules.json'
    a.click()
    URL.revokeObjectURL(a.href)
  }
  const importJSON = async (f: File) => {
    try {
      const parsed = JSON.parse(await f.text())
      if (Array.isArray(parsed)) {
        setRules(parsed)
        setDirty(true)
      }
    } catch {
      setError('not a valid rules JSON file')
    }
  }

  return (
    <section className="card">
      <h2>
        Access rules <span className="count">{rules.length}</span>
        <div className="spacer" />
        <button className="ghost" onClick={exportJSON}>export</button>
        <button className="ghost" onClick={() => fileRef.current?.click()}>import</button>
        <input ref={fileRef} type="file" accept=".json" hidden
          onChange={(e) => e.target.files?.[0] && importJSON(e.target.files[0])} />
      </h2>
      {rules.length === 0 ? (
        <p className="muted">
          No rules — <b>everything is allowed</b> inside the network. Add a rule to start
          restricting; rules are checked top-down, first match wins, and anything unmatched
          is blocked.
        </p>
      ) : (
        <p className="muted small">
          Checked top-down, first match wins; traffic matching no rule is <b>blocked</b>.
        </p>
      )}
      {rules.map((r, i) => (
        <div key={i} className="rulerow">
          <span className="muted rulenum">{i + 1}</span>
          <select
            className={r.action === 'allow' ? 'act allow' : 'act deny'}
            value={r.action}
            onChange={(e) => update(i, { action: e.target.value as ACLRule['action'] })}
          >
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
          <DevicePick label="from" devices={devices} ids={r.src_ids}
            onChange={(ids) => update(i, { src_ids: ids })} />
          <span className="muted">→</span>
          <DevicePick label="to" devices={devices} ids={r.dst_ids}
            onChange={(ids) => update(i, { dst_ids: ids })} />
          <select value={r.protocol}
            onChange={(e) => update(i, { protocol: e.target.value as ACLRule['protocol'],
              ports: e.target.value === 'tcp' || e.target.value === 'udp' ? r.ports : [] })}>
            <option value="">any proto</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
          {(r.protocol === 'tcp' || r.protocol === 'udp') && (
            <input className="ports" placeholder="ports e.g. 22, 8000-9000"
              value={r.ports.join(', ')}
              onChange={(e) => update(i, {
                ports: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
              })} />
          )}
          <div className="spacer" />
          <button className="ghost" onClick={() => move(i, -1)} disabled={i === 0}>↑</button>
          <button className="ghost" onClick={() => move(i, 1)} disabled={i === rules.length - 1}>↓</button>
          <button className="ghost danger" onClick={() => mutate((rs) => rs.filter((_, j) => j !== i))}>✕</button>
        </div>
      ))}
      <div className="keybar" style={{ marginTop: 12 }}>
        <button className="ghost" onClick={() =>
          mutate((rs) => [...rs, { action: 'deny', src_ids: [], dst_ids: [], protocol: 'tcp', ports: [] }])}>
          + add rule
        </button>
        <button onClick={save} disabled={saving || !dirty}>
          {saving ? 'saving…' : dirty ? 'save rules' : 'saved ✓'}
        </button>
        {dirty && <span className="muted small">unsaved changes — devices update the moment you save</span>}
      </div>
      {error && <div className="error">{error}</div>}
      <RuleTester devices={devices} dirty={dirty} />
    </section>
  )
}

// DevicePick toggles between "any device" and an explicit chip set.
function DevicePick({ label, devices, ids, onChange }:
  { label: string; devices: Device[]; ids: number[]; onChange: (ids: number[]) => void }) {
  const [open, setOpen] = useState(false)
  const names = ids
    .map((id) => devices.find((d) => d.id === id)?.hostname ?? `#${id}`)
    .join(', ')
  return (
    <span className="devpick">
      <button className="ghost" onClick={() => setOpen(!open)}>
        {label} {ids.length === 0 ? 'any device' : names}
      </button>
      {open && (
        <span className="chips">
          <button className={ids.length === 0 ? 'chip on' : 'chip'}
            onClick={() => { onChange([]); setOpen(false) }}>any</button>
          {devices.map((d) => {
            const on = ids.includes(d.id)
            return (
              <button key={d.id} className={on ? 'chip on' : 'chip'}
                onClick={() => onChange(on ? ids.filter((x) => x !== d.id) : [...ids, d.id])}>
                {d.hostname}
              </button>
            )
          })}
        </span>
      )}
    </span>
  )
}

// RuleTester answers "can A reach B:22?" against the SAVED rules.
function RuleTester({ devices, dirty }: { devices: Device[]; dirty: boolean }) {
  const [src, setSrc] = useState(0)
  const [dst, setDst] = useState(0)
  const [proto, setProto] = useState('tcp')
  const [port, setPort] = useState('22')
  const [result, setResult] = useState<null | boolean>(null)

  const run = async () => {
    const r = await api.checkACL(src, dst, proto, proto === 'icmp' ? 0 : Number(port) || 0)
    setResult(r.allowed)
  }
  if (devices.length < 1) return null
  return (
    <div className="keybar tester">
      <span className="muted">test:</span>
      <select value={src} onChange={(e) => { setSrc(Number(e.target.value)); setResult(null) }}>
        <option value={0}>from…</option>
        {devices.map((d) => <option key={d.id} value={d.id}>{d.hostname}</option>)}
      </select>
      <span className="muted">→</span>
      <select value={dst} onChange={(e) => { setDst(Number(e.target.value)); setResult(null) }}>
        <option value={0}>to…</option>
        {devices.map((d) => <option key={d.id} value={d.id}>{d.hostname}</option>)}
      </select>
      <select value={proto} onChange={(e) => { setProto(e.target.value); setResult(null) }}>
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
        <option value="icmp">icmp (ping)</option>
      </select>
      {proto !== 'icmp' && (
        <input className="ports short" value={port}
          onChange={(e) => { setPort(e.target.value); setResult(null) }} />
      )}
      <button className="ghost" onClick={run} disabled={!src || !dst}>check</button>
      {result !== null && (
        <span className={result ? 'pill online' : 'pill offline'}>
          {result ? 'allowed ✓' : 'blocked ✕'}
        </span>
      )}
      {dirty && result !== null && <span className="muted small">(tests run against saved rules)</span>}
    </div>
  )
}

// Users: admin-only account management + the open-signup toggle.
function Users({ signupEnabled }: { signupEnabled: boolean }) {
  const [users, setUsers] = useState<User[]>([])
  const [signup, setSignup] = useState(signupEnabled)
  const [name, setName] = useState('')
  const [pw, setPw] = useState('')
  const [role, setRole] = useState('member')
  const [error, setError] = useState('')

  const refresh = useCallback(() => {
    api.users().then(setUsers).catch(() => {})
  }, [])
  useEffect(refresh, [refresh])

  const act = async (fn: () => Promise<unknown>) => {
    setError('')
    try {
      await fn()
      refresh()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'request failed')
    }
  }

  return (
    <section className="card">
      <h2>
        Users <span className="count">{users.length}</span>
        <div className="spacer" />
        <label className="muted small" title="When on, anyone who can reach this page can create a member account">
          <input
            type="checkbox"
            checked={signup}
            onChange={(e) => act(async () => {
              await api.setSignup(e.target.checked)
              setSignup(e.target.checked)
            })}
          />{' '}
          open signup page
        </label>
      </h2>
      <div className="keybar">
        <input className="ports" placeholder="username" value={name}
          onChange={(e) => setName(e.target.value)} />
        <input className="ports" type="password" placeholder="password (8+ chars)" value={pw}
          onChange={(e) => setPw(e.target.value)} />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="member">member</option>
          <option value="admin">admin</option>
        </select>
        <button disabled={!name || pw.length < 8}
          onClick={() => act(async () => {
            await api.createUser(name, pw, role)
            setName(''); setPw('')
          })}>
          + add user
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {users.map((u) => (
        <div key={u.id} className={u.disabled ? 'keyrow dead' : 'keyrow'}>
          <span className="name">{u.username}</span>
          <select value={u.role}
            onChange={(e) => act(() => api.updateUser(u.id, { role: e.target.value }))}>
            <option value="admin">admin</option>
            <option value="member">member</option>
          </select>
          <span className="muted tags">
            {u.disabled && 'disabled · '}created {ago(u.created)}
          </span>
          <div className="spacer" />
          <button className="ghost" onClick={() => {
            const p = prompt(`New password for ${u.username} (8+ chars):`)
            if (p) act(() => api.updateUser(u.id, { password: p }))
          }}>
            reset password
          </button>
          <button className="ghost" onClick={() => act(() => api.updateUser(u.id, { disabled: !u.disabled }))}>
            {u.disabled ? 'enable' : 'disable'}
          </button>
          <button className="ghost danger" onClick={() => {
            if (confirm(`Delete user ${u.username}? Their devices stay in the mesh (admin-owned).`))
              act(() => api.deleteUser(u.id))
          }}>
            delete
          </button>
        </div>
      ))}
      <p className="muted small">
        Members see and manage only their own devices and setup keys; devices enroll under
        the account whose setup key they use.
      </p>
    </section>
  )
}

// Audit: read-only trail of security-relevant actions.
function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [open, setOpen] = useState(false)

  const refresh = useCallback(() => {
    api.audit(100).then(setEntries).catch(() => {})
  }, [])
  useEffect(() => {
    if (open) refresh()
  }, [open, refresh])

  return (
    <section className="card">
      <h2>
        Audit log
        <div className="spacer" />
        <button className="ghost" onClick={() => (open ? refresh() : setOpen(true))}>
          {open ? 'refresh' : 'show'}
        </button>
      </h2>
      {!open ? (
        <p className="muted small">Logins, user changes, key/device events, rule and route changes.</p>
      ) : entries.length === 0 ? (
        <p className="muted">No entries yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>when</th><th>who</th><th>action</th><th>target</th><th>details</th></tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="muted">{ago(e.ts)}</td>
                <td className="name">{e.username}</td>
                <td><code>{e.action}</code></td>
                <td>{e.target}</td>
                <td className="muted">{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function Logo() {
  return (
    <div className="logo">
      <span className="dot" />
      OverMesh
    </div>
  )
}

function ago(unix: number): string {
  if (!unix) return 'never'
  const d = unix * 1000 - Date.now()
  const abs = Math.abs(d)
  const units: [number, string][] = [
    [86400_000, 'd'],
    [3600_000, 'h'],
    [60_000, 'm'],
    [1000, 's'],
  ]
  for (const [ms, label] of units) {
    if (abs >= ms) {
      const v = Math.round(abs / ms)
      return d < 0 ? `${v}${label} ago` : `in ${v}${label}`
    }
  }
  return 'now'
}
