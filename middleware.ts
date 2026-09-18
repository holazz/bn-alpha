import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'

export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const origin = request.headers.get('origin')
    const referer = request.headers.get('referer')
    const host = request.headers.get('host')
    const forwardedHost = request.headers.get('x-forwarded-host')
    const forwardedProto = request.headers.get('x-forwarded-proto')
    const defaultAllowedDomains = ['http://localhost:3000', 'https://bn-alpha.site', 'https://www.bn-alpha.site']
    const dynamicAllowedDomains = new Set(defaultAllowedDomains)

    const normalizeProtocol = (protocol?: string | null) => {
      if (!protocol)
        return null
      return protocol.endsWith(':') ? protocol.slice(0, -1) : protocol
    }

    const appendOrigin = (hostValue?: string | null, protocol?: string | null) => {
      if (!hostValue)
        return
      const normalizedProtocol = normalizeProtocol(protocol) ?? 'https'
      const baseHost = hostValue.split(',')[0]?.trim()
      if (!baseHost)
        return
      dynamicAllowedDomains.add(`${normalizedProtocol}://${baseHost}`)
    }

    if (request.nextUrl.origin)
      dynamicAllowedDomains.add(request.nextUrl.origin)

    appendOrigin(request.nextUrl.host, request.nextUrl.protocol)
    appendOrigin(host, forwardedProto ?? request.nextUrl.protocol)
    appendOrigin(forwardedHost, forwardedProto)

    const allowedDomains = Array.from(dynamicAllowedDomains)

    const getRefererOrigin = (value?: string | null) => {
      if (!value)
        return null
      try {
        return new URL(value).origin
      }
      catch {
        return null
      }
    }

    const refererOrigin = getRefererOrigin(referer)
    const inferredSameHostOrigin = request.nextUrl.host
      ? `${normalizeProtocol(request.nextUrl.protocol) ?? 'https'}://${request.nextUrl.host}`
      : null

    const isValidOrigin = !!origin && dynamicAllowedDomains.has(origin)
    const isValidReferer = !!refererOrigin && dynamicAllowedDomains.has(refererOrigin)
    const isMissingCorsHeaders = !origin && !referer
    const isSameHostRequest = isMissingCorsHeaders && !!inferredSameHostOrigin && dynamicAllowedDomains.has(inferredSameHostOrigin)

    if (!isValidOrigin && !isValidReferer && !isSameHostRequest)
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

    const userAgent = request.headers.get('user-agent')
    const blockedUserAgents = ['curl/', 'wget/', 'python-requests/', 'postman', 'insomnia', 'httpie']

    if (userAgent && blockedUserAgents.some(blocked => userAgent.toLowerCase().includes(blocked))) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const response = NextResponse.next()

    const fallbackOrigin = request.nextUrl.origin ?? inferredSameHostOrigin ?? allowedDomains[0]
    const corsOrigin = (isValidOrigin && origin)
      || (isValidReferer && refererOrigin)
      || (isSameHostRequest && inferredSameHostOrigin)
      || fallbackOrigin

    // CORS Headers
    response.headers.set('Access-Control-Allow-Origin', corsOrigin)
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
    response.headers.set('Access-Control-Max-Age', '86400')

    // Security Headers
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('X-XSS-Protection', '1; mode=block')

    return response
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/api/:path*'],
}
