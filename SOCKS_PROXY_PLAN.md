# Plan: SOCKS Proxy Support

## Problem

`undici`'s `EnvHttpProxyAgent` only supports HTTP/HTTPS proxies. SOCKS4/SOCKS5 proxies (common in corporate environments, SSH tunnels, `proxychains`) are not supported.

## Approach

Use the [`socks`](https://www.npmjs.com/package/socks) package to create a custom undici `Agent` with a SOCKS-aware `connect` function, then set it as the global dispatcher. Local/loopback destinations are bypassed to avoid breaking internal auth coordination.

## Changes

### 1. Add dependency

```
pnpm add socks
```

(`socks` is pure JS, no native deps, well-maintained — same package that backs `socks-proxy-agent`)

### 2. New CLI flag

Add `--socks-proxy <url>` in `parseCommandLineArgs` (`src/lib/utils.ts`):

```
--socks-proxy socks5://127.0.0.1:8080
```

Supports `socks4://`, `socks5://`, `socks4a://`, `socks5h://`. DNS resolution behavior depends on the scheme:

- `socks5://` / `socks4://` — We resolve DNS locally (A records, plus AAAA fallback for SOCKS5) and pass the resolved IP to the SOCKS server.
- `socks5h://` / `socks4a://` — Hostname is sent as-is to the SOCKS server, which performs DNS resolution on its side.

This flag is mutually exclusive with `--enable-proxy` — error if both are provided.

### 3. Create a SOCKS dispatcher

New file `src/lib/socks-dispatcher.ts`:

- Parse the SOCKS proxy URL into host, port, type (4/5), DNS behavior (`h` suffix), and optional auth
- Create an `undici.Agent` with a custom `connect` option that:
  1. Bypasses the proxy for loopback destinations (`127.0.0.1`, `localhost`, `::1`, `[::1]`) — these are used by `coordination.ts` for inter-instance auth polling and must connect directly
  2. Uses `SocksClient.createConnection()` from the `socks` package to establish the SOCKS tunnel
  3. Handles TLS upgrade for HTTPS destinations (wrap the socket with `tls.connect()`), with error handling and socket cleanup
  4. Bridges all errors (SOCKS connection failures, TLS failures) to the `callback(err)` path

```typescript
import { Agent, buildConnector } from 'undici'
import { SocksClient, SocksProxy } from 'socks'
import tls from 'tls'
import net from 'net'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]'])

interface SocksProxyConfig {
  host: string
  port: number
  type: 4 | 5
  userId?: string
  password?: string
  proxyDns: boolean // true for socks5h:// and socks4a://
}

export function parseSocksUrl(proxyUrl: string): SocksProxyConfig {
  const url = new URL(proxyUrl)
  const protocol = url.protocol.replace(':', '')

  let type: 4 | 5
  let proxyDns: boolean

  switch (protocol) {
    case 'socks4':
      type = 4
      proxyDns = false
      break
    case 'socks4a':
      type = 4
      proxyDns = true
      break
    case 'socks5h':
      type = 5
      proxyDns = true
      break
    case 'socks5':
      type = 5
      proxyDns = false
      break
    default:
      throw new Error(`Unsupported SOCKS protocol: ${protocol}. Use socks4://, socks4a://, socks5://, or socks5h://`)
  }

  const port = url.port ? parseInt(url.port, 10) : 1080 // SOCKS default port
  if (isNaN(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid SOCKS proxy port: ${url.port}. Must be a number between 1 and 65535.`)
  }

  return {
    host: url.hostname,
    port,
    type,
    userId: url.username || undefined,
    password: url.password || undefined,
    proxyDns,
  }
}

export function redactProxyUrl(proxyUrl: string): string {
  const url = new URL(proxyUrl)
  if (url.username || url.password) {
    url.username = '***'
    url.password = '***'
  }
  return url.toString()
}

export function createSocksDispatcher(proxyUrl: string): Agent {
  const config = parseSocksUrl(proxyUrl)

  // Default connector for loopback bypass
  const directConnect = buildConnector({})

  return new Agent({
    connect: (opts, callback) => {
      const { hostname, port, protocol } = opts

      // Bypass proxy for loopback addresses (auth coordination uses localhost)
      if (LOOPBACK_HOSTS.has(hostname)) {
        directConnect(opts, callback)
        return
      }

      // For socks5/socks4 (proxyDns=false), resolve DNS locally before connecting.
      // For socks5h/socks4a (proxyDns=true), pass hostname as-is so the proxy resolves DNS.
      //
      // The `socks` package decides DNS behavior based on destination.host:
      // - If it's an IP address, it connects directly
      // - If it's a hostname, it resolves locally by default
      // To force proxy-side DNS, we pass the hostname as-is (which is the default).
      // To force local DNS, we resolve it ourselves first.
      const getDestination = async (): Promise<{ host: string; port: number }> => {
        const destPort = parseInt(String(port), 10)
        if (config.proxyDns || net.isIP(hostname)) {
          // Proxy resolves DNS, or it's already an IP — pass as-is
          return { host: hostname, port: destPort }
        }
        // Local DNS resolution: resolve hostname to IP before passing to SOCKS
        // SOCKS4 only supports IPv4, so skip AAAA lookup and fail clearly
        // SOCKS5 tries A first, falls back to AAAA for dual-stack support
        const dns = await import('dns/promises')
        let resolved: string | undefined
        try {
          const v4 = await dns.resolve4(hostname)
          if (v4.length) resolved = v4[0]
        } catch {}
        if (!resolved && config.type === 5) {
          try {
            const v6 = await dns.resolve6(hostname)
            if (v6.length) resolved = v6[0]
          } catch {}
        }
        if (!resolved) {
          const detail = config.type === 4
            ? `(no A records found; SOCKS4 does not support IPv6)`
            : `(no A or AAAA records)`
          throw new Error(`DNS resolution failed for ${hostname} ${detail}`)
        }
        return { host: resolved, port: destPort }
      }

      getDestination().then((destination) => {
        const socksOpts = {
          proxy: {
            host: config.host,
            port: config.port,
            type: config.type,
            userId: config.userId,
            password: config.password,
          } as SocksProxy,
          command: 'connect' as const,
          destination,
        }

        return SocksClient.createConnection(socksOpts)
      })
        .then(({ socket }) => {
          if (protocol === 'https:') {
            let done = false
            const tlsSocket = tls.connect({
              socket: socket as net.Socket,
              servername: hostname,
            })

            const onError = (err: Error) => {
              if (done) return
              done = true
              tlsSocket.removeListener('secureConnect', onSecureConnect)
              socket.destroy()
              callback(err, null)
            }

            const onSecureConnect = () => {
              if (done) return
              done = true
              tlsSocket.removeListener('error', onError)
              callback(null, tlsSocket)
            }

            tlsSocket.once('error', onError)
            tlsSocket.once('secureConnect', onSecureConnect)
          } else {
            callback(null, socket as net.Socket)
          }
        })
        .catch((err) => {
          callback(err, null)
        })
    },
  })
}
```

Key design decisions:
- **Loopback bypass**: `coordination.ts` uses `fetch('http://127.0.0.1:${port}/wait-for-auth')` for inter-instance auth polling. Routing these through a SOCKS proxy would break multi-instance coordination. The connector checks `LOOPBACK_HOSTS` and falls back to `undici.buildConnector()` for direct connections.
- **No async/callback mixing**: The connector avoids `async` in the callback-style API. SOCKS connection is handled via `.then()/.catch()` and TLS upgrade uses `once` event listeners with a `done` guard flag, ensuring `callback` is called exactly once regardless of error timing.
- **Socket cleanup on TLS failure**: If `tls.connect()` fails, the raw SOCKS socket is destroyed to prevent leaks.
- **Credential redaction**: `redactProxyUrl()` is used in logging (see section 4) to avoid leaking credentials.

### 4. Wire it up in `parseCommandLineArgs`

In `src/lib/utils.ts`, validate mutual exclusivity **before** setting any dispatcher. Move the `--socks-proxy` parsing alongside `--enable-proxy` but gate dispatcher setup:

```typescript
const enableProxy = args.includes('--enable-proxy')
const socksProxyIndex = args.indexOf('--socks-proxy')

// --socks-proxy present but missing value
if (socksProxyIndex !== -1 && (socksProxyIndex >= args.length - 1 || args[socksProxyIndex + 1].startsWith('--'))) {
  log('Error: --socks-proxy requires a URL argument (e.g. --socks-proxy socks5://127.0.0.1:1080)')
  process.exit(1)
}

const hasSocksProxy = socksProxyIndex !== -1 && socksProxyIndex < args.length - 1

// Validate mutual exclusivity before setting any dispatcher
if (enableProxy && hasSocksProxy) {
  log('Error: --socks-proxy and --enable-proxy are mutually exclusive')
  process.exit(1)
}

if (enableProxy) {
  setGlobalDispatcher(new EnvHttpProxyAgent())
  log('HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables')
}

if (hasSocksProxy) {
  const socksUrl = args[socksProxyIndex + 1]
  const dispatcher = createSocksDispatcher(socksUrl)
  setGlobalDispatcher(dispatcher)
  log(`SOCKS proxy enabled: ${redactProxyUrl(socksUrl)}`)
}
```

This ensures:
- No dispatcher is set if both flags are present (we exit first)
- Credentials in the SOCKS URL are redacted in log output

### 5. Update README

Add a section under Flags:

```json
"args": [
  "mcp-remote",
  "https://remote.mcp.server/sse",
  "--socks-proxy",
  "socks5://127.0.0.1:8080"
]
```

Document supported schemes:
- `socks5://` — SOCKS5, local DNS resolution
- `socks5h://` — SOCKS5, proxy-side DNS resolution
- `socks4://` — SOCKS4, local DNS resolution
- `socks4a://` — SOCKS4a, proxy-side DNS resolution

Note: `--socks-proxy` and `--enable-proxy` cannot be used together.

## What doesn't need to change

- No changes to `proxy.ts`, `client.ts`, or `node-oauth-client-provider.ts`
- No changes to `coordination.ts` — loopback bypass in the dispatcher handles it
- No changes to the SSE/HTTP transport logic — undici's global dispatcher handles it transparently
- No changes to the OAuth flow

## Risks

1. **TLS handling**: The custom `connect` function must correctly handle TLS upgrade for HTTPS targets. Need to pass `servername` for SNI and respect `NODE_EXTRA_CA_CERTS` (Node handles this automatically via `tls.connect` defaults). Raw socket is destroyed on TLS error to prevent leaks.
2. **undici `connect` API stability**: The custom connector API is documented but not as commonly used — pin the undici version or test across versions.
3. **DNS resolution**: `socks5h://` and `socks4a://` resolve DNS on the proxy side (hostname sent as-is to SOCKS server). `socks5://` and `socks4://` resolve locally — we call `resolve4()` first, then `resolve6()` as a fallback for SOCKS5 only (SOCKS4 does not support IPv6 and fails early). We do not rely on implicit `socks` package DNS behavior — local resolution is explicit in our code, making the behavior deterministic and testable.

## Testing

### Unit tests (`src/lib/socks-dispatcher.test.ts`)

1. **`parseSocksUrl`**:
   - Parses `socks5://host:port` → type 5, proxyDns false
   - Parses `socks5h://host:port` → type 5, proxyDns true
   - Parses `socks4://host:port` → type 4, proxyDns false
   - Parses `socks4a://host:port` → type 4, proxyDns true
   - Parses credentials from URL (`socks5://user:pass@host:port`)
   - Defaults to port 1080 when port is omitted (`socks5://host`)
   - Throws on invalid port (`socks5://host:0`, `socks5://host:99999`, `socks5://host:abc`) — may throw from `new URL()` or `parseSocksUrl` depending on runtime, assert only that it throws
   - Throws on unsupported protocol (`http://host:port`)

2. **`redactProxyUrl`**:
   - Redacts credentials: `socks5://user:pass@host:1080` → `socks5://***:***@host:1080`
   - Passes through URLs without credentials unchanged

3. **Loopback bypass**:
   - Verify that connections to `127.0.0.1`, `localhost`, `::1`, `[::1]` bypass the SOCKS proxy (use a mock SOCKS server that rejects all connections — loopback requests should still succeed)

4. **Error handling**:
   - SOCKS connection failure calls `callback(err)` (mock `SocksClient.createConnection` to reject)
   - DNS resolution failure (for non-`h` schemes) calls `callback(err)`
   - TLS upgrade failure destroys the raw socket and calls `callback(err)` exactly once (verify no double-callback via a call-count assertion)
   - Post-`secureConnect` socket errors do not trigger a second `callback` (verify `done` guard)

5. **DNS resolution behavior**:
   - `socks5://` with a hostname destination resolves DNS locally (tries A then AAAA) and passes the resolved IP to `SocksClient`
   - `socks5://` with an AAAA-only hostname falls back to `resolve6()` and passes the IPv6 address to `SocksClient`
   - `socks4://` with an AAAA-only hostname does **not** attempt `resolve6()` and fails with a clear error mentioning SOCKS4 IPv6 limitation
   - `socks5h://` with a hostname destination passes the hostname as-is to `SocksClient` (no `resolve4` call)
   - `socks5://` with an IP destination skips DNS resolution

### Integration tests (in `parseCommandLineArgs` tests in `utils.test.ts`)

6. **Mutual exclusivity**: passing both `--enable-proxy` and `--socks-proxy` exits with error
7. **Missing value**: `--socks-proxy` without a following argument (or followed by another flag like `--debug`) exits with a clear error
8. **`--socks-proxy` parses and sets dispatcher**: verify `setGlobalDispatcher` is called

### Manual tests

9. Run with `ssh -D 8080 host` as a SOCKS5 proxy, verify full OAuth + MCP transport works end-to-end
10. Run with `socks5h://` and verify DNS resolution happens on the proxy side (test with a hostname only resolvable from the proxy network)
11. Run with `socks5://` and verify DNS resolution happens locally (verify `resolve4` is invoked, proxy only sees the resolved IP)
