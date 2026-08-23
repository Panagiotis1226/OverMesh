import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, Device, SetupKey, ServerStatus } from './api'

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
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.login(password)
      await onSuccess()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'login failed')
      setBusy(false)
    }
  }

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <Logo />
        <p className="muted">Sign in to manage your mesh</p>
        <input
          type="password"
          placeholder="admin password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        {error && <div className="error">{error}</div>}
        <button disabled={busy || !password}>{busy ? 'signing in…' : 'sign in'}</button>
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

  return (
    <div className="page">
      <header>
        <Logo />
        <div className="net muted">
          network <b>{server.network}</b> · {server.v4_prefix} · {server.v6_prefix}
        </div>
        <div className="spacer" />
        <span className="muted version">{server.version}</span>
        <button className="ghost" onClick={onLogout}>
          log out
        </button>
      </header>
      {error && <div className="error banner">{error}</div>}
      <Devices devices={devices} onChanged={refresh} />
      <SetupKeys keys={keys} onChanged={refresh} />
      <footer className="muted">
        Join a device: <code>overmesh up -server &lt;this-host&gt;:41641 -key sk-…</code>
      </footer>
    </div>
  )
}

function Devices({ devices, onChanged }: { devices: Device[]; onChanged: () => void }) {
  const remove = async (d: Device) => {
    if (!confirm(`Remove ${d.hostname} from the mesh? It will lose connectivity immediately.`)) return
    await api.deleteDevice(d.id)
    onChanged()
  }

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

function SetupKeys({ keys, onChanged }: { keys: SetupKey[]; onChanged: () => void }) {
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
        <KeyRow key={k.id} k={k} onChanged={onChanged} />
      ))}
    </section>
  )
}

function KeyRow({ k, onChanged }: { k: SetupKey; onChanged: () => void }) {
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
