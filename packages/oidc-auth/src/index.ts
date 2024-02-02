/**
 * OpenID Connect authentication middleware for hono
 */

import type { Context } from 'hono'
import { createMiddleware } from 'hono/factory'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { sign, verify } from 'hono/jwt'
import * as oauth2 from 'oauth4webapi'

declare module 'hono' {
  interface ContextVariableMap {
    oidcAuthorizationServer : Promise<oauth2.AuthorizationServer>
    oidcClient: oauth2.Client
    oidcAuth: OidcAuth| null
    oidcSessionCookie: string
  }
}

export type OidcAuth = {
  sub: string
  email: string
  rtk: string // refresh token
  rtkexp: number // token expiration time ; refresh token if it's expired
  ssnexp: number // session expiration time; if it's expired, revoke session and redirect to IdP
}

const oidcSessionCookieName = 'oidc-session'
const defaultRefreshInterval = 15 * 60 // 15 minutes
const defaultExpirationInterval = 60 * 60 * 24 // 1 day

/**
 * Returns the OAuth2 authorization server metadata.
 * If the metadata is not cached, it will be retrieved from the discovery endpoint.
 */
export const getAuthorizationServer = async (c: Context) : Promise<oauth2.AuthorizationServer> => {
  let as = await c.get('oidcAuthorizationServer')
  if (as === undefined) {
    const issuer = new URL(c.env.OIDC_ISSUER)
    const response = await oauth2.discoveryRequest(issuer)
    as = await oauth2.processDiscoveryResponse(issuer, response)
    c.set('oidcAuthorizationServer', as)
  }
  return as
}

/**
 * Returns the OAuth2 client metadata.
 */
export const getClient = (c: Context) : oauth2.Client => {
  let client = c.get('oidcClient')
  if (client === undefined) {
    client = {
      client_id: c.env.OIDC_CLIENT_ID,
      client_secret: c.env.OIDC_CLIENT_SECRET,
      token_endpoint_auth_method: 'client_secret_basic',
    }
    c.set('oidcClient', client)
  }
  return client
}

/**
 * Validates and parses session JWT and returns the OIDC user metadata.
 * If the session is invalid or expired, revokes the session and returns null.
 */
export const getAuth = async (c: Context): Promise<OidcAuth | null> => {
  let auth = c.get('oidcAuth')
  if (auth === undefined) {
    const session_jwt = getCookie(c, oidcSessionCookieName)
    if (session_jwt === undefined) {
      return null
    }
    auth = await verify(session_jwt, c.env.OIDC_SESSION_SECRET)
    if (auth === null || auth.rtkexp === undefined || auth.ssnexp === undefined) {
      throw new Error('Invalid session')
    }
    const now = Math.floor(Date.now() / 1000);
    // Revoke the session if it has expired
    if (auth.ssnexp < now) {
      revokeSession(c)
      return null
    }
    if (auth.rtkexp < now) {
      // Refresh the token if it has expired
      if (auth.rtk === undefined || auth.rtk === "") {
        deleteCookie(c, oidcSessionCookieName)
        return null
      }
      const as = await getAuthorizationServer(c)
      const client = getClient(c)
      const response = await oauth2.refreshTokenGrantRequest(as, client, auth.rtk)
      const result = await oauth2.processRefreshTokenResponse(as, client, response)
      if (oauth2.isOAuth2Error(result)) {
        // The refresh_token might be expired or revoked
        deleteCookie(c, oidcSessionCookieName)
        return null
      }
      auth = await updateAuth(c, auth, result)
    }
    c.set('oidcAuth', auth)
  }
  return auth
}

/**
 * Generates a new session JWT and sets the session cookie.
 */
const setAuth = async (c: Context, response: oauth2.OpenIDTokenEndpointResponse): Promise<OidcAuth> => {
  return updateAuth(c, undefined, response)
}

/**
 * Updates the session JWT and sets the new session cookie.
 */
const updateAuth = async (c: Context, orig: OidcAuth | undefined, response: oauth2.OpenIDTokenEndpointResponse | oauth2.TokenEndpointResponse): Promise<OidcAuth> => {
  const claims = oauth2.getValidatedIdTokenClaims(response)
  const session_refresh_interval = parseInt(c.env.OIDC_SESSION_REFRESH_INTERVAL) || defaultRefreshInterval
  const session_expires = parseInt(c.env.OIDC_SESSION_EXPIRES) || defaultExpirationInterval
  const updated: OidcAuth = {
    sub: claims?.sub || orig?.sub || '',
    email: claims?.email as string || orig?.email || '',
    rtk: response.refresh_token || orig?.rtk || '',
    rtkexp: Math.floor(Date.now() / 1000) + session_refresh_interval,
    ssnexp: orig?.ssnexp || Math.floor(Date.now() / 1000) + session_expires,
  }
  const session_jwt = await sign(updated, c.env.OIDC_SESSION_SECRET)
  setCookie(c, oidcSessionCookieName, session_jwt, { path: '/', httpOnly: true, secure: true })
  c.set('oidcSessionCookie', session_jwt)
  return updated
}

/**
 * Revokes the refresh token of the current session and deletes the session cookie
 */
export const revokeSession = async (c: Context): Promise<void> => {
  const session_jwt = getCookie(c, oidcSessionCookieName)
  if (session_jwt !== undefined) {
    deleteCookie(c, oidcSessionCookieName)
    const payload: OidcAuth = await verify(session_jwt, c.env.OIDC_SESSION_SECRET)
    if (payload.rtk !== undefined && payload.rtk !== "") {
      // revoke refresh token
      const as = await getAuthorizationServer(c)
      const client = getClient(c)
      if (as.revocation_endpoint !== undefined) {
        const response = await oauth2.revocationRequest(as, client, payload.rtk)
        const result = await oauth2.processRevocationResponse(response)
        if (oauth2.isOAuth2Error(result)) {
          throw new Error(`OAuth2Error: [${result.error}] ${result.error_description}`)
        }
      }
    }
  }
  c.set('oidcAuth', undefined)
} 

/**
 * Generates the authorization request URL for the OpenID Connect flow.
 * @param c - The Hono context object.
 * @param state - The state parameter for CSRF protection.
 * @param nonce - The nonce parameter for replay attack protection.
 * @param code_challenge - The code challenge for PKCE (Proof Key for Code Exchange).
 * @returns The authorization request URL.
 * @throws Error if OpenID Connect or email scopes are not supported by the authorization server.
 */
const generateAuthorizationRequestUrl = async (c: Context, state: string, nonce: string, code_challenge: string) => {
  const as = await getAuthorizationServer(c)
  const client = getClient(c)
  const authorizationRequestUrl = new URL(as.authorization_endpoint!)
  authorizationRequestUrl.searchParams.set('client_id', client.client_id)
  authorizationRequestUrl.searchParams.set('redirect_uri', c.env.OIDC_REDIRECT_URI)
  authorizationRequestUrl.searchParams.set('response_type', 'code')
  if (as.scopes_supported === undefined || as.scopes_supported.length === 0) {
    throw new Error('The supported scopes information is not provided by the IdP')
  } else if (as.scopes_supported.indexOf('email') === -1) {
    throw new Error('The "email" scope is not supported by the IdP')
  } else if (as.scopes_supported.indexOf('offline_access') === -1) {
    authorizationRequestUrl.searchParams.set('scope', 'openid email')
  } else {
    authorizationRequestUrl.searchParams.set('scope', 'openid email offline_access')
  }
  authorizationRequestUrl.searchParams.set('state', state)
  authorizationRequestUrl.searchParams.set('nonce', nonce)
  authorizationRequestUrl.searchParams.set('code_challenge', code_challenge)
  authorizationRequestUrl.searchParams.set('code_challenge_method', 'S256')
  if (as.issuer === 'https://accounts.google.com') {
    // Google requires 'access_type=offline' and 'prompt=consent' to obtain a refresh token
    authorizationRequestUrl.searchParams.set('access_type', 'offline')
    authorizationRequestUrl.searchParams.set('prompt', 'consent')
  }
  return authorizationRequestUrl.toString()
}

/**
 * Processes the OAuth2 callback request.
 */
export const processOAuthCallback = async (c: Context) => {
  const as = await getAuthorizationServer(c)
  const client = getClient(c)

  // Parses the authorization response and validates the state parameter
  const state = getCookie(c, 'state')
  deleteCookie(c, 'state')
  const currentUrl: URL = new URL(c.req.url)
  const params = oauth2.validateAuthResponse(as, client, currentUrl, state)
  if (oauth2.isOAuth2Error(params)) {
    throw new Error(`OAuth2Error: [${params.error}] ${params.error_description}`)
  }

  // Exchanges the authorization code for a refresh token
  const code = c.req.query('code')
  const nonce = getCookie(c, 'nonce')
  deleteCookie(c, 'nonce')
  const code_verifier = getCookie(c, 'code_verifier')
  deleteCookie(c, 'code_verifier')
  const continue_url = getCookie(c, 'continue')
  deleteCookie(c, 'continue')
  if (code === undefined || nonce === undefined || code_verifier === undefined) {
    throw new Error('Missing required parameters / cookies')
  }
  const result = await exchangeAuthorizationCode(as, client, params, c.env.OIDC_REDIRECT_URI, nonce, code_verifier)
  await setAuth(c, result)
  return c.redirect(continue_url || '/')
}

/**
 * Exchanges the authorization code for a refresh token.
 */
const exchangeAuthorizationCode = async (as: oauth2.AuthorizationServer, client: oauth2.Client, params: URLSearchParams, redirect_uri: string, nonce: string, code_verifier: string) => {
  const response = await oauth2.authorizationCodeGrantRequest(
    as,
    client,
    params,
    redirect_uri,
    code_verifier,
  )
  // Handle www-authenticate challenges
  const challenges = oauth2.parseWwwAuthenticateChallenges(response)
  if (challenges !== undefined) {
    for (const challenge of challenges) {
      console.log('challenge: ', challenge)
    }
    throw new Error()
  }
  const result = await oauth2.processAuthorizationCodeOpenIDResponse(as, client, response, nonce)
  if (oauth2.isOAuth2Error(result)) {
    throw new Error(`OAuth2Error: [${result.error}] ${result.error_description}`)
  }
  return result
}

/**
 * Returns a middleware that requires OIDC authentication.
 */
export const oidcAuthMiddleware = ()  => {
  return createMiddleware(async (c, next) => {
    const uri = c.req.url.split('?')[0]
    if (uri === c.env.OIDC_REDIRECT_URI) {
      return processOAuthCallback(c)
    }
    try {
      const auth = await getAuth(c)
      if (auth === null) {
        // Redirect to IdP for login
        const state = oauth2.generateRandomState()
        const nonce = oauth2.generateRandomNonce()
        const code_verifier = oauth2.generateRandomCodeVerifier()
        const code_challenge = await oauth2.calculatePKCECodeChallenge(code_verifier)
        const url = await generateAuthorizationRequestUrl(c, state, nonce, code_challenge)
        setCookie(c, 'state', state, { path: '/' , httpOnly: true, secure: true})
        setCookie(c, 'nonce', nonce, { path: '/' , httpOnly: true, secure: true})
        setCookie(c, 'code_verifier', code_verifier, { path: '/' , httpOnly: true, secure: true})
        setCookie(c, 'continue', c.req.url, { path: '/' , httpOnly: true, secure: true})
        return c.redirect(url)
      }
    } catch (e) {
      console.log(e)
      deleteCookie(c, oidcSessionCookieName)
      throw new Error('Invalid session')
    }
    await next()
    c.res.headers.set('Cache-Control', 'private, no-cache')
    // Workaround to set the session cookie when the response is returned by the origin server
    const sessionCookie = c.get('oidcSessionCookie')
    if (sessionCookie !== undefined) {
      setCookie(c, oidcSessionCookieName, sessionCookie, { path: '/', httpOnly: true, secure: true })
    }
  })
}