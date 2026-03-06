import { Agent, buildConnector } from 'undici'
import { SocksClient, type SocksProxy } from 'socks'
import tls from 'tls'
import net from 'net'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]'])

export interface SocksProxyConfig {
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

  // Strip brackets from IPv6 proxy host (e.g. [::1] -> ::1)
  const host = url.hostname.startsWith('[') && url.hostname.endsWith(']') ? url.hostname.slice(1, -1) : url.hostname

  return {
    host,
    port,
    type,
    userId: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
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
    connect: (opts: any, callback: any) => {
      const { hostname, port, protocol } = opts

      // Bypass proxy for loopback addresses (auth coordination uses localhost)
      if (LOOPBACK_HOSTS.has(hostname)) {
        directConnect(opts, callback)
        return
      }

      // Strip brackets from IPv6 literals (e.g. [::1] -> ::1) for SOCKS destination and TLS servername
      const bareHostname = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname

      // For socks5/socks4 (proxyDns=false), resolve DNS locally before connecting.
      // For socks5h/socks4a (proxyDns=true), pass hostname as-is so the proxy resolves DNS.
      const getDestination = async (): Promise<{ host: string; port: number }> => {
        // undici passes port as "" (empty string) when the URL uses the default port
        const destPort = port ? parseInt(String(port), 10) : protocol === 'https:' ? 443 : 80
        if (config.proxyDns || net.isIP(bareHostname)) {
          // Proxy resolves DNS, or it's already an IP — pass unbracketed
          return { host: bareHostname, port: destPort }
        }
        // Local DNS resolution: resolve hostname to IP before passing to SOCKS
        // SOCKS4 only supports IPv4, so skip AAAA lookup and fail clearly
        // SOCKS5 tries A first, falls back to AAAA for dual-stack support
        const dns = await import('dns/promises')
        let resolved: string | undefined
        try {
          const v4 = await dns.resolve4(bareHostname)
          if (v4.length) resolved = v4[0]
        } catch {}
        if (!resolved && config.type === 5) {
          try {
            const v6 = await dns.resolve6(bareHostname)
            if (v6.length) resolved = v6[0]
          } catch {}
        }
        if (!resolved) {
          const detail = config.type === 4 ? `(no A records found; SOCKS4 does not support IPv6)` : `(no A or AAAA records)`
          throw new Error(`DNS resolution failed for ${bareHostname} ${detail}`)
        }
        return { host: resolved, port: destPort }
      }

      getDestination()
        .then((destination) => {
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
              servername: bareHostname,
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
