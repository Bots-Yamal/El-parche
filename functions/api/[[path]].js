
const COOKIE = "parche_session";
const SESSION_DAYS = 7;
const ITERATIONS = 310000;
const SERVER_ID = "el-parche";

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extra
    }
  });
}

function cookieValue(request) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return match ? match[1] : null;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return bytesToBase64(result);
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: base64ToBytes(salt),
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return bytesToBase64(result);
}

async function newPassword(password) {
  const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await passwordHash(password, salt);
  return { salt, hash };
}

function validUsername(username) {
  return typeof username === "string" &&
    /^[a-zA-Z0-9_-]{3,24}$/.test(username);
}

function validPassword(password, minimum = 10) {
  return typeof password === "string" &&
    password.length >= minimum &&
    password.length <= 128;
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    throw new Error("Solicitud inválida.");
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    server_id: user.server_id
  };
}

async function createSession(user, env) {
  const token = bytesToBase64(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const tokenHash = await sha256(token);
  const expires = Date.now() + SESSION_DAYS * 86400000;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, user.id, expires).run();

  return new Response(JSON.stringify({
    user: publicUser(user)
  }), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Set-Cookie":
        `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`
    }
  });
}

async function getUser(request, env) {
  const token = cookieValue(request);
  if (!token) return null;

  const tokenHash = await sha256(token);

  const result = await env.DB.prepare(`
    SELECT accounts.*, sessions.expires_at
    FROM sessions
    JOIN accounts ON accounts.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).bind(tokenHash).first();

  if (!result || result.expires_at < Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).run();
    return null;
  }

  return result;
}

function requireRole(user, roles) {
  return !!user && roles.includes(user.role);
}

function cleanAnswers(answers) {
  if (!answers || typeof answers !== "object" || Array.isArray(answers)) {
    throw new Error("Formulario inválido.");
  }

  const keys = [
    "p1","p2","p3","p4","p5","p6","p7","p8",
    "s1","s2","s3","s4","s5","s6","s7","s8","s9"
  ];

  const result = {};

  for (const key of keys) {
    const value = answers[key];

    if (typeof value !== "string" || value.length > 1200) {
      throw new Error("Hay respuestas inválidas o demasiado largas.");
    }

    result[key] = value.trim();
  }

  for (const key of keys) {
    if (!result[key]) throw new Error("Debes completar todas las preguntas.");
  }

  const age1 = Number(result.p3);
  const age2 = Number(result.s4);

  if (!Number.isInteger(age1) || age1 < 13 || age1 > 99 ||
      !Number.isInteger(age2) || age2 < 13 || age2 > 99) {
    throw new Error("Comprueba las edades introducidas.");
  }

  if (!/^\d{17,20}$/.test(result.s3)) {
    throw new Error("El ID de Discord no tiene un formato válido.");
  }

  return result;
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "");
  const method = request.method;

  if (method !== "GET") {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) {
      return json({ error: "Origen no permitido." }, 403);
    }
  }

  // Comprobar si ya existe un SuperAdmin.
  if (path === "/api/setup-status" && method === "GET") {
    const admin = await env.DB.prepare(
      "SELECT id FROM accounts WHERE role = 'superadmin' LIMIT 1"
    ).first();

    return json({ configured: !!admin });
  }

  // Crear el primer SuperAdmin, una sola vez.
  if (path === "/api/setup" && method === "POST") {
    const data = await body(request);

    if (!env.BOOTSTRAP_SECRET ||
        data.secret !== env.BOOTSTRAP_SECRET) {
      return json({ error: "Secreto incorrecto." }, 403);
    }

    if (!validUsername(data.username) ||
        !validPassword(data.password, 12)) {
      return json({ error: "Usuario o contraseña no válidos." }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM accounts WHERE role = 'superadmin' LIMIT 1"
    ).first();

    if (existing) {
      return json({ error: "La configuración inicial ya fue realizada." }, 409);
    }

    const credentials = await newPassword(data.password);

    const result = await env.DB.prepare(`
      INSERT INTO accounts
      (username, password_hash, salt, role, server_id, created_at)
      VALUES (?, ?, ?, 'superadmin', NULL, ?)
    `).bind(
      data.username,
      credentials.hash,
      credentials.salt,
      new Date().toISOString()
    ).run();

    return json({ success: true, id: result.meta.last_row_id }, 201);
  }

  // Registro público: siempre crea una cuenta normal.
  if (path === "/api/register" && method === "POST") {
    const data = await body(request);

    if (!validUsername(data.username) ||
        !validPassword(data.password)) {
      return json({
        error: "Usa un usuario de 3 a 24 caracteres y una contraseña de al menos 10."
      }, 400);
    }

    const exists = await env.DB.prepare(
      "SELECT id FROM accounts WHERE username = ? COLLATE NOCASE"
    ).bind(data.username).first();

    if (exists) {
      return json({ error: "Ese nombre de usuario ya está ocupado." }, 409);
    }

    const credentials = await newPassword(data.password);

    try {
      await env.DB.prepare(`
        INSERT INTO accounts
        (username, password_hash, salt, role, server_id, created_at)
        VALUES (?, ?, ?, 'user', ?, ?)
      `).bind(
        data.username,
        credentials.hash,
        credentials.salt,
        SERVER_ID,
        new Date().toISOString()
      ).run();
    } catch {
      return json({ error: "No se pudo crear la cuenta." }, 400);
    }

    return json({ success: true }, 201);
  }

  // Inicio de sesión.
  if (path === "/api/login" && method === "POST") {
    const data = await body(request);

    if (typeof data.username !== "string" ||
        typeof data.password !== "string") {
      return json({ error: "Completa usuario y contraseña." }, 400);
    }

    const user = await env.DB.prepare(`
      SELECT * FROM accounts
      WHERE username = ? COLLATE NOCASE
      AND suspended = 0
    `).bind(data.username).first();

    if (!user) {
      return json({ error: "Usuario o contraseña incorrectos." }, 401);
    }

    const hash = await passwordHash(data.password, user.salt);

    if (hash !== user.password_hash) {
      return json({ error: "Usuario o contraseña incorrectos." }, 401);
    }

    return createSession(user, env);
  }

  // Sesión actual.
  if (path === "/api/me" && method === "GET") {
    const user = await getUser(request, env);
    if (!user) return json({ error: "Inicia sesión." }, 401);
    return json({ user: publicUser(user) });
  }

  // Cerrar sesión.
  if (path === "/api/logout" && method === "POST") {
    const token = cookieValue(request);

    if (token) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash = ?"
      ).bind(await sha256(token)).run();
    }

    return json({ success: true }, 200, {
      "Set-Cookie":
        `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
    });
  }

  const user = await getUser(request, env);

  // Enviar postulación.
  if (path === "/api/applications" && method === "POST") {
    if (!user || user.role !== "user") {
      return json({ error: "No tienes permiso para postularte." }, 403);
    }

    const data = await body(request);
    let answers;

    try {
      answers = cleanAnswers(data.answers);
    } catch (error) {
      return json({ error: error.message }, 400);
    }

    const result = await env.DB.prepare(`
      INSERT INTO applications
      (user_id, server_id, answers_json, status, note, created_at, updated_at)
      VALUES (?, ?, ?, 'pending', '', ?, ?)
    `).bind(
      user.id,
      SERVER_ID,
      JSON.stringify(answers),
      new Date().toISOString(),
      new Date().toISOString()
    ).run();

    return json({
      success: true,
      id: result.meta.last_row_id
    }, 201);
  }

  // Listar postulaciones según el rol.
  if (path === "/api/applications" && method === "GET") {
    if (!user) return json({ error: "Inicia sesión." }, 401);

    let query;
    let params;

    if (user.role === "user") {
      query = `
        SELECT applications.*, accounts.username
        FROM applications JOIN accounts ON accounts.id = applications.user_id
        WHERE applications.user_id = ?
        ORDER BY applications.id DESC
      `;
      params = [user.id];
    } else if (user.role === "owner") {
      query = `
        SELECT applications.*, accounts.username
        FROM applications JOIN accounts ON accounts.id = applications.user_id
        WHERE applications.server_id = ?
        ORDER BY applications.id DESC
      `;
      params = [user.server_id];
    } else if (user.role === "superadmin") {
      query = `
        SELECT applications.*, accounts.username
        FROM applications JOIN accounts ON accounts.id = applications.user_id
        ORDER BY applications.id DESC
      `;
      params = [];
    } else {
      return json({ error: "Acceso denegado." }, 403);
    }

    const result = await env.DB.prepare(query).bind(...params).all();

    const applications = (result.results || []).map(a => ({
      id: a.id,
      username: a.username,
      status: a.status,
      note: user.role === "user" ? a.note : a.note,
      created_at: a.created_at
    }));

    return json({ applications });
  }

  // Leer una postulación individual.
  const applicationMatch = path.match(/^\/api\/applications\/(\d+)$/);

  if (applicationMatch && method === "GET") {
    if (!user) return json({ error: "Inicia sesión." }, 401);

    const application = await env.DB.prepare(`
      SELECT applications.*, accounts.username
      FROM applications
      JOIN accounts ON accounts.id = applications.user_id
      WHERE applications.id = ?
    `).bind(Number(applicationMatch[1])).first();

    if (!application) return json({ error: "No existe esa postulación." }, 404);

    const allowed =
      user.role === "superadmin" ||
      (user.role === "owner" && user.server_id === application.server_id) ||
      (user.role === "user" && user.id === application.user_id);

    if (!allowed) return json({ error: "No tienes permiso para leerla." }, 403);

    return json({
      application: {
        id: application.id,
        username: application.username,
        status: application.status,
        note: application.note,
        created_at: application.created_at,
        answers: JSON.parse(application.answers_json)
      }
    });
  }

  // Revisar una postulación.
  if (path === "/api/review" && method === "POST") {
    if (!requireRole(user, ["owner", "superadmin"])) {
      return json({ error: "Solo un administrador puede revisar postulaciones." }, 403);
    }

    const data = await body(request);

    if (!Number.isInteger(Number(data.id)) ||
        !["pending", "accepted", "rejected"].includes(data.status) ||
        typeof data.note !== "string" ||
        data.note.length > 1000) {
      return json({ error: "Datos de revisión inválidos." }, 400);
    }

    const application = await env.DB.prepare(
      "SELECT * FROM applications WHERE id = ?"
    ).bind(Number(data.id)).first();

    if (!application) return json({ error: "Postulación no encontrada." }, 404);

    if (user.role === "owner" && user.server_id !== application.server_id) {
      return json({ error: "No puedes modificar postulaciones de otro servidor." }, 403);
    }

    await env.DB.prepare(`
      UPDATE applications
      SET status = ?, note = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      data.status,
      data.note.trim(),
      new Date().toISOString(),
      application.id
    ).run();

    return json({ success: true });
  }

  // Crear Owner: solo SuperAdmin.
  if (path === "/api/owners" && method === "POST") {
    if (!requireRole(user, ["superadmin"])) {
      return json({ error: "Solo SuperAdmin puede crear Owners." }, 403);
    }

    const data = await body(request);

    if (!validUsername(data.username) ||
        !validPassword(data.password, 12)) {
      return json({ error: "Usuario o contraseña no válidos." }, 400);
    }

    const exists = await env.DB.prepare(
      "SELECT id FROM accounts WHERE username = ? COLLATE NOCASE"
    ).bind(data.username).first();

    if (exists) return json({ error: "Ese usuario ya existe." }, 409);

    const credentials = await newPassword(data.password);

    await env.DB.prepare(`
      INSERT INTO accounts
      (username, password_hash, salt, role, server_id, created_at)
      VALUES (?, ?, ?, 'owner', ?, ?)
    `).bind(
      data.username,
      credentials.hash,
      credentials.salt,
      SERVER_ID,
      new Date().toISOString()
    ).run();

    return json({ success: true }, 201);
  }

  return json({ error: "Ruta no encontrada." }, 404);
}

export async function onRequest(context) {
  try {
    return await handle(context.request, context.env);
  } catch (error) {
    return json({ error: "Error interno del servidor." }, 500);
  }
}
