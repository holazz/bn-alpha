import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'

export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const origin = request.headers.get('origin')
    const referer = request.headers.get('referer')
    const host = request.headers.get('host')
    const defaultAllowedDomains = ['http://localhost:3000', 'https://bn-alpha.site', 'https://www.bn-alpha.site']
    const dynamicAllowedDomains = new Set(defaultAllowedDomains)

    if (request.nextUrl.origin)
      dynamicAllowedDomains.add(request.nextUrl.origin)

    if (host)
      dynamicAllowedDomains.add(`${request.nextUrl.protocol}//${host}`)

    const allowedDomains = Array.from(dynamicAllowedDomains)
    const isValidOrigin = !!origin && dynamicAllowedDomains.has(origin)
    const isValidReferer = !!referer && allowedDomains.some(domain => referer.startsWith(domain))
    const isMissingCorsHeaders = !origin && !referer
    const isSameHostRequest = isMissingCorsHeaders && !!host && host === request.nextUrl.host

    if (!isValidOrigin && !isValidReferer && !isSameHostRequest)
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

    const userAgent = request.headers.get('user-agent')
    const blockedUserAgents = ['curl/', 'wget/', 'python-requests/', 'postman', 'insomnia', 'httpie']

    if (userAgent && blockedUserAgents.some(blocked => userAgent.toLowerCase().includes(blocked))) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const response = NextResponse.next()

    let corsOrigin = request.nextUrl.origin ?? allowedDomains[0]

    if (isValidOrigin && origin) {
      corsOrigin = origin
    }
    else if (referer && isValidReferer) {
      try {
        corsOrigin = new URL(referer).origin
      }
      catch {
        corsOrigin = request.nextUrl.origin ?? allowedDomains[0]
      }
    }
    else if (isSameHostRequest && request.nextUrl.origin) {
      corsOrigin = request.nextUrl.origin
    }

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
