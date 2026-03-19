import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any
  let mockReadTextFileOptional: any
  let mockWriteTextFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)
    mockReadTextFileOptional = vi.mocked(mcpAuthConfig.readTextFileOptional)
    mockWriteTextFile = vi.mocked(mcpAuthConfig.writeTextFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
    mockReadTextFileOptional.mockResolvedValue(undefined)
    mockWriteTextFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })

  describe('token expiry tracking', () => {
    const NOW = 1_700_000_000_000

    beforeEach(() => {
      vi.useFakeTimers()
      vi.setSystemTime(NOW)
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('should compute remaining TTL by subtracting elapsed time', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const savedAt = NOW - 600_000 // 600 seconds ago

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce(String(savedAt))

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3000)
    })

    it('should clamp expires_in to 0 when token is fully expired', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const savedAt = NOW - 7_200_000 // 2 hours ago

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce(String(savedAt))

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(0)
    })

    it('should preserve original expires_in for legacy tokens without timestamp file', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'legacy-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'legacy-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce(undefined)

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3600)
    })

    it('should not modify tokens when expires_in is undefined and timestamp is missing', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce(undefined)

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBeUndefined()
    })

    it('should write both tokens.json and tokens_saved_at.txt on save', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const tokensToSave = {
        access_token: 'new-access-token',
        token_type: 'bearer' as const,
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
      }

      await provider.saveTokens(tokensToSave)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', tokensToSave)
      expect(mockWriteTextFile).toHaveBeenCalledWith('test-hash', 'tokens_saved_at.txt', String(NOW))
    })

    it('should delete tokens_saved_at.txt when invalidating tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens_saved_at.txt')
    })

    it('should delete tokens_saved_at.txt when invalidating all credentials', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens_saved_at.txt')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'code_verifier.txt')
    })

    it('should cap remaining time at original expires_in when clock skew causes negative elapsed', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const savedAt = NOW + 60_000 // savedAt in the future (clock skew)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce(String(savedAt))

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3600)
    })

    it('should preserve original expires_in when timestamp file contains empty string', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce('')

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3600)
    })

    it('should preserve original expires_in when timestamp file contains non-numeric content', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockResolvedValueOnce('not-a-number')

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3600)
    })

    it('should preserve original expires_in when readTextFileOptional throws', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      mockReadJsonFile.mockResolvedValueOnce({
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
      })
      mockReadTextFileOptional.mockRejectedValueOnce(new Error('permission denied'))

      const tokens = await provider.tokens()

      expect(tokens).toBeDefined()
      expect(tokens!.expires_in).toBe(3600)
    })
  })
})
