// Thin typed client for the overmesh-server admin API.

export type Device = {
  id: number
  hostname: string
  ipv4: string
  ipv6: string
  os: string
  online: boolean
  last_seen: number
  created: number
}

export type SetupKey = {
  id: number
  key: string
  reusable: boolean
  revoked: boolean
  expired: boolean
  expires_at: number
  used_count: number
  created: number
}

export type ServerStatus = {
  version: string
  network: string
  v4_prefix: string
  v6_prefix: string
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const j = await res.json()
      if (j.error) msg = j.error
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg)
  }
  return res.json() as Promise<T>
}

export const api = {
  login: (password: string) => req<{ ok: boolean }>('POST', '/api/login', { password }),
  logout: () => req<{ ok: boolean }>('POST', '/api/logout', {}),
  status: () => req<ServerStatus>('GET', '/api/status'),
  devices: () => req<Device[]>('GET', '/api/devices'),
  deleteDevice: (id: number) => req<{ ok: boolean }>('DELETE', `/api/devices/${id}`),
  setupKeys: () => req<SetupKey[]>('GET', '/api/setupkeys'),
  createSetupKey: (reusable: boolean, expiresHours: number) =>
    req<SetupKey>('POST', '/api/setupkeys', { reusable, expires_hours: expiresHours }),
  revokeSetupKey: (id: number) => req<{ ok: boolean }>('DELETE', `/api/setupkeys/${id}`),
}
