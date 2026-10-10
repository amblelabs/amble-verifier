import { Hono } from "hono";
import { setCookie, getCookie, deleteCookie } from "hono/cookie";
import { sign, verify } from "hono/jwt";

type Bindings = {
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  GUILD_ID: string;
  TARGET_ROLE_IDS: string;
  JWT_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();
const DISCORD_API = "https://discord.com/api/v10";
const REDIRECT_URI = "https://amble-verifier.amblelabs.workers.dev/callback";

function generateState(): string {
  return crypto.randomUUID();
}

app.get("/auth", async (c) => {
  const state = generateState();
  setCookie(c, "oauth_state", state, {
    httpOnly: true,
    maxAge: 600,
    secure: true,
  });

  const port = c.req.query("port");
  if (port) {
    setCookie(c, "redirect_port", port, { httpOnly: true, maxAge: 600 });
  }

  const discordAuthUrl = `https://discord.com/oauth2/authorize?response_type=code&client_id=${c.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=identify%20guilds.members.read&state=${state}`;
  return c.redirect(discordAuthUrl);
});

app.get("/callback", async (c) => {
  const code = c.req.query("code");
  const returnedState = c.req.query("state");
  const savedState = getCookie(c, "oauth_state");
  deleteCookie(c, "oauth_state");

  if (!returnedState || !savedState || returnedState !== savedState) {
    return c.text("Invalid state parameter", 400);
  }
  if (!code) {
    return c.text("Missing authorization code", 400);
  }

  const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: c.env.DISCORD_CLIENT_ID,
      client_secret: c.env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code: code,
      redirect_uri: REDIRECT_URI,
    }),
  });

  const tokenData: any = await tokenResponse.json();
  if (!tokenResponse.ok) {
    return c.text(`Token exchange failed: ${tokenData.error_description}`, 401);
  }
  const accessToken = tokenData.access_token;

  const memberResponse = await fetch(
    `${DISCORD_API}/users/@me/guilds/${c.env.GUILD_ID}/member`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  );

  if (!memberResponse.ok) {
    return c.text("User is not a member of the required guild", 403);
  }
  const memberData: any = await memberResponse.json();
  const userRoles: string[] = memberData.roles || [];

  let foundRole = false;
  for (const roleId of c.env.TARGET_ROLE_IDS.split(";")) {
    if (userRoles.includes(roleId)) {
      foundRole = true;
    }
  }

  if (!foundRole) {
    return c.text("Forbidden: You do not have the required role.", 403);
  }

  const payload = {
    sub: memberData.user.id,
    username: memberData.user.username,
    roles: userRoles,
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
  };
  const jwt = await sign(payload, c.env.JWT_SECRET);
  setCookie(c, "auth_token", jwt, {
    httpOnly: true,
    maxAge: 3600,
    secure: true,
  });

  const port = getCookie(c, "redirect_port");
  deleteCookie(c, "redirect_port");
  const redirectUrl = port
    ? `http://localhost:${port}/callback?token=${encodeURIComponent(jwt)}`
    : "https://amblelabs.dev/verified";
  return c.redirect(redirectUrl);
});

app.get("/verify", async (c) => {
  const token =
    getCookie(c, "auth_token") || c.req.header("Authorization")?.split(" ")[1];
  if (!token) {
    return c.json({ valid: false, error: "No token provided" }, 401);
  }
  try {
    const payload = await verify(token, c.env.JWT_SECRET, { alg: 'HS256' });
    return c.json({ valid: true, user: payload });
  } catch (e) {
      
  console.error('Verification error:', e);
    return c.json({ valid: false, error: "Invalid token" }, 401);
  }
});

export default app;
