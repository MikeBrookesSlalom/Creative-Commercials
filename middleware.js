// Gates the entire site behind a password-only login page (no username field,
// no browser-native Basic Auth popup). No external dependencies — plain Web
// APIs only, so there's nothing that can fail to resolve at the edge.
//
// Crawler blocking for the real page content comes from the <meta name="robots">
// tag baked into index.html and the blanket-disallow robots.txt, not from
// this file — that keeps this middleware simple and dependency-free.

export const config = {
  matcher: '/:path*',
};

const PASSWORD = 'llamas';
const COOKIE_NAME = 'site_auth';
// Opaque session token — not derived from the password, so the cookie value
// alone reveals nothing about the password. Anyone who already has this exact
// string could skip the password, same limitation as sharing the password.
const SESSION_TOKEN = 'sq7-argx-slalom-2026-session-ok';

const ROBOTS_HEADER_VALUE = 'noindex, nofollow, noarchive, nosnippet, noimageindex, noai, noimageai';

function loginPage({ error } = {}) {
  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="${ROBOTS_HEADER_VALUE}">
<title>Sign in</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Avenir Next","Avenir Next LT Pro",Avenir,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(115deg,#0B426E 0%,#0B5FB0 40%,#3f8a6e 72%,#91C454 100%);padding:20px}
  .card{background:#fff;border-radius:18px;padding:38px 34px;max-width:360px;width:100%;
    box-shadow:0 20px 60px rgba(10,20,40,.35)}
  h1{font-size:16px;font-weight:800;color:#141922;margin-bottom:4px;letter-spacing:-.2px}
  p{font-size:13px;color:#6B7280;margin-bottom:20px}
  input[type=password]{width:100%;padding:12px 14px;font-size:15px;border:1.5px solid #E4E8EE;
    border-radius:10px;margin-bottom:14px;font-family:inherit}
  input[type=password]:focus{outline:none;border-color:#0B5FB0}
  button{width:100%;padding:12px 14px;font-size:15px;font-weight:700;color:#fff;border:none;
    border-radius:10px;background:linear-gradient(110deg,#0B426E,#0B5FB0 55%,#5E9B2E);
    cursor:pointer;font-family:inherit}
  button:hover{filter:brightness(1.06)}
  .err{background:#fdeceb;color:#c0392b;border:1px solid #f5c6c0;border-radius:8px;
    padding:9px 12px;font-size:12.5px;margin-bottom:14px}
</style>
</head>
<body>
  <form class="card" method="POST">
    <h1>Slalom &times; argenx</h1>
    <p>Enter the password to continue.</p>
    ${error ? '<div class="err">Incorrect password &mdash; please try again.</div>' : ''}
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Enter</button>
  </form>
</body>
</html>`;
}

function htmlResponse(html, status) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Robots-Tag': ROBOTS_HEADER_VALUE,
    },
  });
}

function hasValidSession(request) {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  return !!match && match[1] === SESSION_TOKEN;
}

export default async function middleware(request) {
  const { pathname } = new URL(request.url);

  // robots.txt must always be reachable, and is itself a blanket disallow —
  // let it pass straight through to origin, untouched.
  if (pathname === '/robots.txt') {
    return;
  }

  if (hasValidSession(request)) {
    // Already signed in — pass through to the real content untouched.
    // (The page itself carries its own noindex/noai meta tag.)
    return;
  }

  if (request.method === 'POST') {
    let password = '';
    try {
      const form = await request.formData();
      password = form.get('password') || '';
    } catch (_) {
      password = '';
    }

    if (password === PASSWORD) {
      const redirectUrl = new URL(pathname || '/', request.url);
      // Build the redirect manually — Response.redirect() returns a response
      // with immutable headers in some runtimes, which throws if you then
      // try to attach a Set-Cookie header to it.
      return new Response(null, {
        status: 303,
        headers: {
          Location: redirectUrl.toString(),
          'Set-Cookie': `${COOKIE_NAME}=${SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
          'X-Robots-Tag': ROBOTS_HEADER_VALUE,
        },
      });
    }

    return htmlResponse(loginPage({ error: true }), 401);
  }

  // GET/HEAD/etc. with no valid session — show the password-only form.
  return htmlResponse(loginPage(), 401);
}
