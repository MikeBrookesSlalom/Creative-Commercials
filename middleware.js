// Edge Middleware: password gate for the whole site.
// - No username, just a single shared password (default: SlalomValue).
// - Change the password without a redeploy by setting a SITE_PASSWORD
//   environment variable in the Vercel project settings.
// - This is a lightweight gate suited to keeping an internal reference off
//   search engines, AI crawlers, and casual link-sharing. It is not built to
//   withstand a determined attacker (no rate limiting, no per-user login).

export const config = {
  // Runs on every request except robots.txt and favicon.ico, which must stay
  // reachable without auth so crawlers can actually read the disallow rules.
  matcher: '/((?!robots\\.txt|favicon\\.ico).*)',
};

const DEFAULT_PASSWORD = 'SlalomValue';
const COOKIE_NAME = 'cc_auth';
const MAX_AGE = 60 * 60 * 24 * 7; // 7 days

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const password =
    (typeof process !== 'undefined' && process.env && process.env.SITE_PASSWORD) ||
    DEFAULT_PASSWORD;
  const expectedCookie = await sha256Hex(password);

  if (url.pathname === '/login') {
    if (request.method === 'POST') {
      let submitted = '';
      try {
        const form = await request.formData();
        submitted = String(form.get('password') || '');
      } catch (e) {
        submitted = '';
      }

      if (submitted === password) {
        const headers = new Headers({ Location: '/' });
        headers.append(
          'Set-Cookie',
          `${COOKIE_NAME}=${expectedCookie}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`
        );
        return new Response(null, { status: 303, headers });
      }

      return Response.redirect(new URL('/login?error=1', request.url), 303);
    }
    // GET /login: let the static login page serve normally, no auth needed.
    return;
  }

  const cookieVal = getCookie(request.headers.get('cookie'), COOKIE_NAME);
  if (cookieVal === expectedCookie) {
    return; // authenticated — let the request through
  }

  return Response.redirect(new URL('/login', request.url), 307);
}
