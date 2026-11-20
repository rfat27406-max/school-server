
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

const FIXED_SESSION_PRICE_DZD = 300;
// Authentication context is resolved per request; never trust a teacher ID from the browser.


function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(x => x.trim())
    .filter(Boolean);

  const allowOrigin = allowed.includes(origin)
    ? origin
    : (allowed.length === 0 ? "*" : "null");

  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(corsHeaders(request, env))) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    headers
  });
}

function localNow() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Africa/Algiers",
    weekday: "long",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23"
  }).formatToParts(new Date());

  return Object.fromEntries(
    parts
      .filter(p => p.type !== "literal")
      .map(p => [p.type, p.value])
  );
}

function dateWeekday(dateString) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateString)) {
    return null;
  }

  const d = new Date(`${dateString}T12:00:00Z`);

  if (
    Number.isNaN(d.getTime()) ||
    d.toISOString().slice(0, 10) !== dateString
  ) {
    return null;
  }

  return d.getUTCDay();
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function bearer(request) {
  const header = request.headers.get("Authorization") || "";

  return header.startsWith("Bearer ")
    ? header.slice(7)
    : "";
}

async function createSession(env, table, ownerColumn, ownerId) {
  const token = `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
  const tokenHash = await sha256(token);
  await env.DB.prepare(`
    INSERT INTO ${table} (id, ${ownerColumn}, token_hash, expires_at)
    VALUES (?, ?, ?, datetime('now', '+30 days'))
  `).bind(crypto.randomUUID(), ownerId, tokenHash).run();
  return token;
}

async function authenticatedAdmin(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(`
    SELECT a.id
    FROM admin_sessions a
    WHERE a.token_hash = ? AND a.revoked_at IS NULL
      AND (a.expires_at IS NULL OR a.expires_at > datetime('now'))
    LIMIT 1
  `).bind(tokenHash).first();
}

async function authenticatedTeacher(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(`
    SELECT t.id, t.name, t.subject, t.education_level
    FROM teacher_sessions ts
    JOIN teachers t ON t.id = ts.teacher_id
    WHERE ts.token_hash = ? AND ts.revoked_at IS NULL
      AND (ts.expires_at IS NULL OR ts.expires_at > datetime('now'))
      AND t.active = 1
    LIMIT 1
  `).bind(tokenHash).first();
}

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function allowLoginAttempt(request, env, purpose) {
  if (!env.RATE_LIMIT_SECRET) return false;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await sha256(`${env.RATE_LIMIT_SECRET}:${ip}`);
  const window = await env.DB.prepare("SELECT strftime('%Y-%m-%dT%H', 'now') AS hour").first();
  const result = await env.DB.prepare(`
    INSERT INTO auth_login_limits (ip_hash, purpose, window_key, attempts)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(ip_hash, purpose, window_key)
    DO UPDATE SET attempts = attempts + 1
    WHERE attempts < 5
    RETURNING attempts
  `).bind(ipHash, purpose, window.hour).first();
  return Boolean(result);
}

async function authenticatedStudent(request, env) {
  const token = bearer(request);

  if (!token) return null;

  const tokenHash = await sha256(token);

  return env.DB.prepare(`
    SELECT s.id, s.first_name, s.last_name, s.age
    FROM student_sessions ss
    JOIN students s ON s.id = ss.student_id
    WHERE ss.token_hash = ?
      AND ss.revoked_at IS NULL
      AND (
        ss.expires_at IS NULL
        OR ss.expires_at > datetime('now')
      )
    LIMIT 1
  `).bind(tokenHash).first();
}

function registrationWindowIsOpen(now) {
  const allowedDay =
    now.weekday === "Friday" ||
    now.weekday === "Saturday";

  const minutes =
    Number(now.hour) * 60 +
    Number(now.minute);

  return allowedDay && minutes >= 450 && minutes < 960;
}


// ---------------- Web Push (RFC 8291 + VAPID) ----------------
const textEncoder = new TextEncoder();
function b64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}
function concatBytes(...arrays) {
  const length = arrays.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const item of arrays) { out.set(item, offset); offset += item.length; }
  return out;
}
async function hkdf(secret, salt, info, length) {
  const key = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}
async function vapidAuthorization(endpoint, env) {
  if (!env.VAPID_PRIVATE_JWK || !env.VAPID_PUBLIC_KEY) throw new Error("VAPID is not configured");
  const origin = new URL(endpoint).origin;
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlEncode(textEncoder.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = b64urlEncode(textEncoder.encode(JSON.stringify({ aud: origin, exp: now + 12 * 60 * 60, sub: env.VAPID_SUBJECT || "mailto:admin@example.com" })));
  const unsigned = `${header}.${payload}`;
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, textEncoder.encode(unsigned)));
  return `vapid t=${unsigned}.${b64urlEncode(signature)}, k=${env.VAPID_PUBLIC_KEY}`;
}
async function encryptPushPayload(subscription, payload) {
  const userPublic = b64urlDecode(subscription.p256dh);
  const authSecret = b64urlDecode(subscription.auth);
  if (userPublic.length !== 65 || authSecret.length < 16) throw new Error("Invalid subscription keys");
  const userKey = await crypto.subtle.importKey("raw", userPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const serverKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: userKey }, serverKeys.privateKey, 256));
  const serverPublic = new Uint8Array(await crypto.subtle.exportKey("raw", serverKeys.publicKey));
  const authInfo = concatBytes(textEncoder.encode("WebPush: info\0"), userPublic, serverPublic);
  const ikm = await hkdf(sharedSecret, authSecret, authInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(ikm, salt, textEncoder.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(ikm, salt, textEncoder.encode("Content-Encoding: nonce\0"), 12);
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const plaintext = concatBytes(textEncoder.encode(JSON.stringify(payload)), new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, aesKey, plaintext));
  const header = new Uint8Array(21 + serverPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = serverPublic.length;
  header.set(serverPublic, 21);
  return concatBytes(header, ciphertext);
}
async function sendWebPush(subscription, payload, env) {
  const body = await encryptPushPayload(subscription, payload);
  const authorization = await vapidAuthorization(subscription.endpoint, env);
  return fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      "Authorization": authorization,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "TTL": "86400",
      "Urgency": "high"
    },
    body
  });
}
async function pushToStudents(env, studentId, payload) {
  const query = studentId
    ? env.DB.prepare("SELECT id, student_id, endpoint, p256dh, auth FROM push_subscriptions WHERE student_id = ?").bind(studentId)
    : env.DB.prepare("SELECT id, student_id, endpoint, p256dh, auth FROM push_subscriptions");
  const { results = [] } = await query.all();
  let sent = 0, failed = 0;
  for (const subscription of results) {
    try {
      const response = await sendWebPush(subscription, payload, env);
      if (response.ok) sent++;
      else {
        failed++;
        if (response.status === 404 || response.status === 410) {
          await env.DB.prepare("DELETE FROM push_subscriptions WHERE id = ?").bind(subscription.id).run();
        }
      }
    } catch (error) {
      failed++;
      console.error("Web Push delivery failed", error);
    }
  }
  return { attempted: results.length, sent, failed };
}
async function deliverUpcomingLessonReminders(env) {
  const now = localNow();
  const today = `${now.year}-${now.month}-${now.day}`;
  const currentMinutes = Number(now.hour) * 60 + Number(now.minute);
  const { results = [] } = await env.DB.prepare(`
    SELECT b.id AS booking_id, b.student_id, b.session_date, g.name AS group_name,
      g.start_time, g.end_time, t.name AS teacher_name
    FROM bookings b
    JOIN groups g ON g.id = b.group_id
    JOIN teachers t ON t.id = g.teacher_id
    WHERE b.session_date = ? AND b.status = 'registered'
      AND b.reminder_sent_at IS NULL
  `).bind(today).all();
  for (const booking of results) {
    const [hour, minute] = String(booking.start_time).split(":").map(Number);
    const minutesUntil = hour * 60 + minute - currentMinutes;
    if (minutesUntil < 25 || minutesUntil > 35) continue;
    const delivery = await pushToStudents(env, booking.student_id, {
      title: "تذكير بموعد حصتك",
      body: `تبقّى حوالي 30 دقيقة على حصة ${booking.group_name} مع الأستاذ ${booking.teacher_name} (${booking.start_time}).`,
      url: "/",
      tag: `lesson-reminder-${booking.booking_id}`,
      kind: "lesson-reminder"
    });
    if (delivery.failed === 0) {
      await env.DB.prepare("UPDATE bookings SET reminder_sent_at = datetime('now') WHERE id = ? AND reminder_sent_at IS NULL")
        .bind(booking.booking_id).run();
    }
  }
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  // Public VAPID key used by the student browser to subscribe.
  if (path === "/api/push/public-key" && request.method === "GET") {
    if (!env.VAPID_PUBLIC_KEY) return json({ error: "خدمة الإشعارات الفورية غير مهيأة بعد." }, 503);
    return json({ publicKey: env.VAPID_PUBLIC_KEY });
  }

  // ==========================================
  // فحص السيرفر
  // ==========================================

  if (path === "/api/health" && request.method === "GET") {
    return json({
      ok: true,
      service: "school-server",
      timezone: "Africa/Algiers"
    });
  }

  // ==========================================
  // تسجيل دخول الإدارة (ADMIN_PASSWORD في Cloudflare Secrets)
  // ==========================================
  if (path === "/api/admin/login" && request.method === "POST") {
    if (!(await allowLoginAttempt(request, env, "admin"))) {
      return json({ error: "تجاوزت عدد محاولات الدخول المسموح بها. حاول لاحقاً." }, 429);
    }
    let body = {};
    try { body = await request.json(); } catch {}
    if (!env.ADMIN_PASSWORD || !constantTimeEqual(String(body.password || ""), env.ADMIN_PASSWORD)) {
      return json({ error: "رمز الإدارة غير صحيح." }, 401);
    }
    const token = await createSession(env, "admin_sessions", "admin_id", "main-admin");
    return json({ access_token: token, token_type: "Bearer" });
  }

  // تسجيل دخول الأستاذ بكلمة المرور التي تحددها الإدارة
  if (path === "/api/teacher/login" && request.method === "POST") {
    if (!(await allowLoginAttempt(request, env, "teacher"))) {
      return json({ error: "تجاوزت عدد محاولات الدخول المسموح بها. حاول لاحقاً." }, 429);
    }
    let body = {};
    try { body = await request.json(); } catch {}
    const teacherId = String(body.teacher_id || "");
    const password = String(body.password || "");
    const teacher = await env.DB.prepare(`
      SELECT id, name, subject, education_level, password_hash
      FROM teachers WHERE id = ? AND active = 1 LIMIT 1
    `).bind(teacherId).first();
    if (!teacher) {
      return json({ error: "بيانات دخول الأستاذ غير صحيحة." }, 401);
    }
    let storedPasswordHash = teacher.password_hash;
    // كلمة المرور الأولية للأستاذ بومدين تُضبط عبر Cloudflare Secret مرة واحدة.
    if (!storedPasswordHash && teacher.id === "teacher-boumediene" && env.BOUMDIENE_INITIAL_PASSWORD) {
      storedPasswordHash = await sha256(env.BOUMDIENE_INITIAL_PASSWORD);
      await env.DB.prepare("UPDATE teachers SET password_hash = ? WHERE id = ? AND password_hash IS NULL")
        .bind(storedPasswordHash, teacher.id).run();
    }
    if (!storedPasswordHash || !constantTimeEqual(await sha256(password), storedPasswordHash)) {
      return json({ error: "بيانات دخول الأستاذ غير صحيحة." }, 401);
    }
    const token = await createSession(env, "teacher_sessions", "teacher_id", teacher.id);
    return json({
      access_token: token,
      token_type: "Bearer",
      teacher: { id: teacher.id, name: teacher.name, subject: teacher.subject, education_level: teacher.education_level }
    });
  }

  // حالة طلب التسجيل: رمز عشوائي خاص بصاحب الطلب فقط.
  if (path === "/api/registration/status" && request.method === "GET") {
    const requestToken = bearer(request);
    if (!requestToken) return json({ error: "رمز متابعة الطلب غير موجود." }, 401);
    const requestHash = await sha256(requestToken);
    const registration = await env.DB.prepare(`
      SELECT id, first_name, last_name, status, rejection_reason, created_at, reviewed_at
      FROM student_registration_requests WHERE token_hash = ? LIMIT 1
    `).bind(requestHash).first();
    if (!registration) return json({ error: "طلب التسجيل غير موجود أو أن رمز المتابعة غير صالح." }, 404);
    return json({ registration });
  }

  // إنشاء جلسة التلميذ بعد اعتماد الطلب فقط.
  if (path === "/api/registration/claim" && request.method === "POST") {
    const requestToken = bearer(request);
    if (!requestToken) return json({ error: "رمز متابعة الطلب غير موجود." }, 401);
    const requestHash = await sha256(requestToken);
    const registration = await env.DB.prepare(`
      SELECT id, student_id, status, claimed_at FROM student_registration_requests
      WHERE token_hash = ? LIMIT 1
    `).bind(requestHash).first();
    if (!registration || registration.status !== "approved" || !registration.student_id) {
      return json({ error: "لم تتم الموافقة على طلبك بعد." }, 403);
    }
    const token = `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
    const result = await env.DB.prepare(`
      INSERT INTO student_sessions (id, student_id, token_hash)
      SELECT ?, ?, ? WHERE EXISTS (
        SELECT 1 FROM student_registration_requests WHERE id = ? AND status = 'approved'
      )
    `).bind(crypto.randomUUID(), registration.student_id, await sha256(token), registration.id).run();
    if (!result.meta?.changes) return json({ error: "تعذر تفعيل جلسة الحساب. أعد المحاولة." }, 409);
    const student = await env.DB.prepare("SELECT id, first_name, last_name, age FROM students WHERE id = ?")
      .bind(registration.student_id).first();
    return json({ access_token: token, token_type: "Bearer", student });
  }

  // جميع مسارات الإدارة تتطلب جلسة إدارة صالحة.
  let adminAuth = null;
  let teacherAuth = null;
  if (path.startsWith("/api/admin/") && path !== "/api/admin/login") {
    adminAuth = await authenticatedAdmin(request, env);
    if (!adminAuth) return json({ error: "يلزم تسجيل دخول الإدارة." }, 401);
  }
  if (path.startsWith("/api/teacher/") && path !== "/api/teacher/login") {
    teacherAuth = await authenticatedTeacher(request, env);

    if (!teacherAuth) return json({ error: "يلزم تسجيل دخول الأستاذ بكلمة مروره الخاصة." }, 401);
  }

  // Save or refresh this student's Web Push subscription.
  if (path === "/api/push/subscribe" && request.method === "POST") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    let body = {};
    try { body = await request.json(); } catch {}
    const endpoint = String(body.endpoint || "");
    const p256dh = String(body.keys?.p256dh || "");
    const auth = String(body.keys?.auth || "");
    if (!endpoint.startsWith("https://") || !p256dh || !auth) return json({ error: "بيانات الاشتراك غير صالحة." }, 400);
    await env.DB.prepare(`
      INSERT INTO push_subscriptions (id, student_id, endpoint, p256dh, auth, last_seen_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(endpoint) DO UPDATE SET student_id = excluded.student_id,
        p256dh = excluded.p256dh, auth = excluded.auth, last_seen_at = datetime('now')
    `).bind(crypto.randomUUID(), student.id, endpoint, p256dh, auth).run();
    return json({ subscribed: true });
  }

  if (path === "/api/push/unsubscribe" && request.method === "POST") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    let body = {};
    try { body = await request.json(); } catch {}
    if (body.endpoint) await env.DB.prepare("DELETE FROM push_subscriptions WHERE student_id = ? AND endpoint = ?")
      .bind(student.id, String(body.endpoint)).run();
    return json({ unsubscribed: true });
  }

  // ملخص مالي شامل للإدارة.
  if (path === "/api/admin/summary" && request.method === "GET") {
    const summary = await env.DB.prepare(`
      SELECT
        (SELECT COUNT(*) FROM students) AS students_count,
        (SELECT COUNT(*) FROM teachers WHERE active = 1) AS teachers_count,
        (SELECT COUNT(*) FROM groups WHERE active = 1) AS groups_count,
        COUNT(CASE WHEN b.payment_status = 'paid' AND b.status != 'cancelled' THEN 1 END) AS paid_count,
        COUNT(CASE WHEN b.payment_status = 'unpaid' AND b.status != 'cancelled' THEN 1 END) AS unpaid_count,
        COALESCE(SUM(CASE WHEN b.payment_status = 'paid' AND b.status != 'cancelled' THEN g.price_dzd ELSE 0 END), 0) AS total_revenue
      FROM bookings b JOIN groups g ON g.id = b.group_id
    `).first();
    const { results: teachers } = await env.DB.prepare(`
      SELECT t.id, t.name, t.subject,
        COUNT(CASE WHEN b.status != 'cancelled' THEN 1 END) AS bookings_count,
        COALESCE(SUM(CASE WHEN b.payment_status = 'paid' AND b.status != 'cancelled' THEN g.price_dzd ELSE 0 END), 0) AS revenue
      FROM teachers t
      LEFT JOIN groups g ON g.teacher_id = t.id
      LEFT JOIN bookings b ON b.group_id = g.id
      WHERE t.active = 1
      GROUP BY t.id ORDER BY t.name
    `).all();
    return json({ summary, teachers });
  }

  // إضافة أستاذ وإنشاء ملفه تلقائياً.
  if (path === "/api/admin/teachers" && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const name = String(body.name || "").trim();
    const subject = String(body.subject || "").trim();
    const level = String(body.education_level || "").trim();
    const password = String(body.password || "");
    if (!name || !subject || !level || password.length < 6) {
      return json({ error: "أدخل اسم الأستاذ والمادة والمستوى وكلمة مرور من 6 أحرف على الأقل." }, 400);
    }
    const id = `teacher-${crypto.randomUUID()}`;
    await env.DB.prepare(`
      INSERT INTO teachers (id, name, subject, education_level, password_hash)
      VALUES (?, ?, ?, ?, ?)
    `).bind(id, name, subject, level, await sha256(password)).run();
    return json({ teacher: { id, name, subject, education_level: level } }, 201);
  }

  // تعيين/تغيير كلمة مرور أستاذ موجود (مثل الأستاذ بومدين).
  const setTeacherPasswordMatch = path.match(/^\/api\/admin\/teachers\/([^/]+)\/password$/);
  if (setTeacherPasswordMatch && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const password = String(body.password || "");
    if (password.length < 6) return json({ error: "كلمة المرور يجب أن تتكون من 6 أحرف على الأقل." }, 400);
    const result = await env.DB.prepare("UPDATE teachers SET password_hash = ? WHERE id = ?")
      .bind(await sha256(password), setTeacherPasswordMatch[1]).run();
    if (!result.meta || result.meta.changes !== 1) return json({ error: "الأستاذ غير موجود." }, 404);
    return json({ message: "تم تحديث كلمة مرور الأستاذ." });
  }

  // إضافة فوج لأستاذ محدد من الإدارة.
  if (path === "/api/admin/groups" && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const teacherId = String(body.teacher_id || "");
    const teacherPassword = String(body.teacher_password || "");
    const name = String(body.name || "").trim();
    const weekday = String(body.weekday || "");
    const start = String(body.start_time || "");
    const end = String(body.end_time || "");
    const price = Number(body.price_dzd ?? 300);
    if (!teacherId || !name || !["friday", "saturday"].includes(weekday) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(start) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(end) || start >= end ||
        !Number.isInteger(price) || price < 0) {
      return json({ error: "بيانات الفوج غير صالحة." }, 400);
    }
    const teacher = await env.DB.prepare("SELECT id, password_hash FROM teachers WHERE id = ? AND active = 1").bind(teacherId).first();
    if (!teacher) return json({ error: "الأستاذ غير موجود." }, 404);
    if (!teacherPassword || !teacher.password_hash ||
        !constantTimeEqual(await sha256(teacherPassword), teacher.password_hash)) {
      return json({ error: "كود الأستاذ غير صحيح؛ لم يتم إنشاء الفوج." }, 401);
    }
    const result = await env.DB.prepare(`
      INSERT INTO groups (teacher_id, name, weekday, start_time, end_time, price_dzd)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(teacherId, name, weekday, start, end, price).run();
    return json({ group_id: result.meta.last_row_id, message: "تم إنشاء الفوج." }, 201);
  }

  // سجل الإشعارات للإدارة.
  if (path === "/api/admin/notifications" && request.method === "GET") {
    const { results } = await env.DB.prepare(`
      SELECT n.id, n.title, n.message, n.audience, n.student_id, n.created_at,
        CASE
          WHEN n.audience = 'all' THEN 'جميع التلاميذ'
          ELSE COALESCE(s.first_name || ' ' || s.last_name, 'تلميذ محدد')
        END AS recipient_name
      FROM notifications n
      LEFT JOIN students s ON s.id = n.student_id
      ORDER BY n.created_at DESC
      LIMIT 100
    `).all();
    return json({ notifications: results });
  }

  // نشر إشعار داخل المنصة، للجميع أو لتلميذ محدد.
  if (path === "/api/admin/notifications" && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const title = String(body.title || "").trim();
    const message = String(body.message || "").trim();
    const audience = String(body.audience || "all");
    const studentId = String(body.student_id || "");

    if (!title || !message || !["all", "student"].includes(audience) ||
        (audience === "student" && !studentId)) {
      return json({ error: "أدخل عنوان الإشعار ونصه وحدد المستلم." }, 400);
    }

    if (audience === "student") {
      const student = await env.DB.prepare(
        "SELECT id FROM students WHERE id = ? LIMIT 1"
      ).bind(studentId).first();
      if (!student) return json({ error: "التلميذ المحدد غير موجود." }, 404);
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO notifications (id, title, message, audience, student_id)
      VALUES (?, ?, ?, ?, ?)
    `).bind(id, title, message, audience, audience === "student" ? studentId : null).run();

    let pushDelivery = { attempted: 0, sent: 0, failed: 0 };
    let pushConfigured = Boolean(env.VAPID_PRIVATE_JWK && env.VAPID_PUBLIC_KEY);
    if (pushConfigured) {
      pushDelivery = await pushToStudents(env, audience === "student" ? studentId : null, {
        title, body: message, url: "/", tag: `admin-notification-${id}`, kind: "announcement"
      });
    }
    return json({
      id,
      message: pushConfigured
        ? `تم نشر الإشعار. وصل إلى ${pushDelivery.sent} جهازاً من أصل ${pushDelivery.attempted} اشتراك.`
        : "تم حفظ الإشعار داخل المنصة، لكن الإشعارات الفورية لم تُهيأ بعد.",
      delivery: pushConfigured ? "web_push" : "in_app",
      push: pushDelivery
    }, 201);
  }

  // ==========================================
  // الإدارة العامة: جميع التلاميذ
  // ==========================================

  // طلبات تسجيل التلاميذ الجديدة.
  if (path === "/api/admin/registration-requests" && request.method === "GET") {
    const { results } = await env.DB.prepare(`
      SELECT id, first_name, last_name, age, status, created_at
      FROM student_registration_requests
      WHERE status = 'pending' ORDER BY created_at ASC
    `).all();
    return json({ requests: results });
  }

  const registrationDecision = path.match(/^\/api\/admin\/registration-requests\/([^/]+)\/decision$/);
  if (registrationDecision && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const decision = String(body.decision || "");
    if (!["approve", "reject"].includes(decision)) return json({ error: "القرار غير صالح." }, 400);
    const requestId = registrationDecision[1];
    const pending = await env.DB.prepare(`SELECT * FROM student_registration_requests WHERE id = ? AND status = 'pending' LIMIT 1`)
      .bind(requestId).first();
    if (!pending) return json({ error: "الطلب غير موجود أو تمت مراجعته مسبقاً." }, 404);
    if (decision === "reject") {
      const reason = String(body.reason || "لم تتم الموافقة على طلب التسجيل.").trim().slice(0, 240);
      await env.DB.batch([
        env.DB.prepare(`UPDATE student_registration_requests SET status = 'rejected', rejection_reason = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'`).bind(reason, requestId),
        env.DB.prepare(`DELETE FROM student_name_registry WHERE normalized_name = ? AND owner_type = 'request' AND owner_id = ?`).bind(pending.normalized_name, requestId)
      ]);
      return json({ message: "تم رفض طلب التسجيل." });
    }
    const studentId = crypto.randomUUID();
    try {
      // Insert the student before assigning student_id to the request.
      // student_registration_requests.student_id has a foreign key to students(id),
      // so the previous order violated the FK constraint on approval.
      // D1 batch executes these statements atomically: any failure rolls back all of them.
      const approvalResults = await env.DB.batch([
        env.DB.prepare(`INSERT INTO students (id, first_name, last_name, age)
          SELECT ?, ?, ?, ?
          WHERE EXISTS (
            SELECT 1 FROM student_registration_requests
            WHERE id = ? AND status = 'pending'
          )`)
          .bind(studentId, pending.first_name, pending.last_name, pending.age, requestId),
        env.DB.prepare(`UPDATE student_registration_requests
          SET status = 'approved', student_id = ?, reviewed_at = datetime('now')
          WHERE id = ? AND status = 'pending'
          AND EXISTS (SELECT 1 FROM students WHERE id = ?)`)
          .bind(studentId, requestId, studentId),
        env.DB.prepare(`UPDATE student_name_registry
          SET owner_type = 'student', owner_id = ?
          WHERE normalized_name = ? AND owner_type = 'request' AND owner_id = ?`)
          .bind(studentId, pending.normalized_name, requestId)
      ]);
      if (!approvalResults[0]?.meta?.changes) return json({ error: "تمت مراجعة هذا الطلب مسبقاً." }, 409);
    } catch (error) {
      return json({ error: "تعذر اعتماد الطلب بسبب تعارض في بيانات الاسم. تحقق من قائمة التلاميذ." }, 409);
    }
    return json({ message: "تمت الموافقة على التلميذ وتفعيل حسابه." });
  }

  if (
    path === "/api/admin/students" &&
    request.method === "GET"
  ) {
    const { results } = await env.DB.prepare(`
      SELECT
        s.id,
        s.first_name,
        s.last_name,
        s.age,
        s.created_at,
        COUNT(b.id) AS bookings_count,
        COALESCE(SUM(
          CASE
            WHEN b.payment_status = 'paid' THEN 1
            ELSE 0
          END
        ), 0) AS paid_count,
        COALESCE(SUM(
          CASE
            WHEN b.payment_status = 'unpaid' THEN 1
            ELSE 0
          END
        ), 0) AS unpaid_count
      FROM students s
      LEFT JOIN bookings b ON b.student_id = s.id
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `).all();

    return json({ students: results });
  }

  // ==========================================
  // الأساتذة
  // ==========================================

  if (
    path === "/api/teachers" &&
    request.method === "GET"
  ) {
    const { results } = await env.DB.prepare(`
      SELECT id, name, subject, education_level,
        (SELECT COUNT(*) FROM groups g WHERE g.teacher_id = teachers.id AND g.active = 1) AS groups_count
      FROM teachers
      WHERE active = 1
      ORDER BY name
    `).all();

    return json({ teachers: results });
  }

  // ==========================================
  // الأفواج العامة
  // ==========================================

  if (
    path === "/api/groups" &&
    request.method === "GET"
  ) {
    const { results } = await env.DB.prepare(`
      SELECT
        g.id,
        g.teacher_id,
        g.name,
        g.weekday,
        g.start_time,
        g.end_time,
        g.price_dzd,
        g.active,
        t.name AS teacher_name,
        t.subject,
        t.education_level
      FROM groups g
      JOIN teachers t ON t.id = g.teacher_id
      WHERE g.active = 1 AND t.active = 1
      ORDER BY t.name, g.weekday, g.start_time
    `).all();

    return json({
      groups: results,
      capacity: "unlimited"
    });
  }

  // الأستاذ يضيف فوجاً إلى حسابه فقط.
  if (path === "/api/teacher/groups" && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch {}
    const name = String(body.name || "").trim();
    const weekday = String(body.weekday || "");
    const start = String(body.start_time || "");
    const end = String(body.end_time || "");
    const price = Number(body.price_dzd ?? 300);
    if (!name || !["friday", "saturday"].includes(weekday) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(start) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(end) || start >= end ||
        !Number.isInteger(price) || price < 0) {
      return json({ error: "بيانات الفوج غير صالحة." }, 400);
    }
    const result = await env.DB.prepare(`
      INSERT INTO groups (teacher_id, name, weekday, start_time, end_time, price_dzd)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(teacherAuth.id, name, weekday, start, end, price).run();
    return json({ group_id: result.meta.last_row_id, message: "تم إنشاء الفوج." }, 201);
  }

  // ==========================================
  // لوحة الأستاذ: أفواجه
  // ==========================================

  if (
    path === "/api/teacher/groups" &&
    request.method === "GET"
  ) {
    const { results } = await env.DB.prepare(`
      SELECT
        g.id,
        g.name,
        g.weekday,
        g.start_time,
        g.end_time,
        g.price_dzd,
        g.active,
        t.name AS teacher_name,
        (
          SELECT COUNT(*)
          FROM bookings b
          WHERE b.group_id = g.id
            AND b.status != 'cancelled'
        ) AS bookings_count
      FROM groups g
      JOIN teachers t ON t.id = g.teacher_id
      WHERE g.teacher_id = ?
        AND g.active = 1
      ORDER BY g.weekday, g.start_time
    `).bind(teacherAuth.id).all();

    return json({ groups: results });
  }

  // ==========================================
  // لوحة الأستاذ: ملخص المداخيل
  // ==========================================

  if (
    path === "/api/teacher/summary" &&
    request.method === "GET"
  ) {
    const summary = await env.DB.prepare(`
      SELECT
        COUNT(DISTINCT b.student_id) AS students_count,

        COUNT(
          CASE
            WHEN b.status != 'cancelled' THEN 1
          END
        ) AS bookings_count,

        COUNT(
          CASE
            WHEN b.payment_status = 'paid'
              AND b.status != 'cancelled'
            THEN 1
          END
        ) AS paid_count,

        COUNT(
          CASE
            WHEN b.payment_status = 'unpaid'
              AND b.status != 'cancelled'
            THEN 1
          END
        ) AS unpaid_count,

        COALESCE(SUM(
          CASE
            WHEN b.payment_status = 'paid'
              AND b.status != 'cancelled'
            THEN g.price_dzd
            ELSE 0
          END
        ), 0) AS total_revenue

      FROM groups g
      LEFT JOIN bookings b ON b.group_id = g.id
      WHERE g.teacher_id = ?
    `).bind(
      teacherAuth.id
    ).first();

    return json({
      summary: {
        students_count: Number(summary.students_count || 0),
        bookings_count: Number(summary.bookings_count || 0),
        paid_count: Number(summary.paid_count || 0),
        unpaid_count: Number(summary.unpaid_count || 0),
        total_revenue: Number(summary.total_revenue || 0),
        session_price: FIXED_SESSION_PRICE_DZD
      }
    });
  }

  // ==========================================
  // لوحة الأستاذ: تلاميذ فوج معين
  //
  // مثال:
  // GET /api/teacher/groups/1/students
  //
  // ويمكن تحديد تاريخ:
  // GET /api/teacher/groups/1/students?date=2026-11-20
  // ==========================================

  const groupStudentsMatch = path.match(
    /^\/api\/teacher\/groups\/(\d+)\/students$/
  );

  if (
    groupStudentsMatch &&
    request.method === "GET"
  ) {
    const groupId = Number(groupStudentsMatch[1]);
    const selectedDate = url.searchParams.get("date");

    if (
      selectedDate &&
      dateWeekday(selectedDate) === null
    ) {
      return json({
        error: "تاريخ الحصة غير صالح."
      }, 400);
    }

    const group = await env.DB.prepare(`
      SELECT
        id,
        teacher_id,
        name,
        weekday,
        start_time,
        end_time,
        price_dzd
      FROM groups
      WHERE id = ?
        AND teacher_id = ?
        AND active = 1
      LIMIT 1
    `).bind(
      groupId,
      teacherAuth.id
    ).first();

    if (!group) {
      return json({
        error: "الفوج غير موجود."
      }, 404);
    }

    let query = `
      SELECT
        b.id AS booking_id,
        b.session_date,
        b.status,
        b.payment_status,
        b.paid_at,
        b.created_at AS booking_created_at,

        s.id AS student_id,
        s.first_name,
        s.last_name,
        s.age,

        g.name AS group_name,
        g.price_dzd

      FROM bookings b
      JOIN students s ON s.id = b.student_id
      JOIN groups g ON g.id = b.group_id

      WHERE b.group_id = ?
        AND g.teacher_id = ?
        AND b.status != 'cancelled'
    `;

    const bindings = [groupId, teacherAuth.id];

    if (selectedDate) {
      query += ` AND b.session_date = ?`;
      bindings.push(selectedDate);
    }

    query += `
      ORDER BY b.session_date DESC, s.first_name, s.last_name
    `;

    const { results } = await env.DB.prepare(query)
      .bind(...bindings)
      .all();

    const paidCount = results.filter(
      item => item.payment_status === "paid"
    ).length;

    const unpaidCount = results.filter(
      item => item.payment_status === "unpaid"
    ).length;

    return json({
      group,
      students: results,
      summary: {
        students_count: results.length,
        paid_count: paidCount,
        unpaid_count: unpaidCount,
        revenue: results.reduce((sum, item) =>
          sum + (item.payment_status === "paid" ? Number(item.price_dzd || 0) : 0), 0)
      },
      session_price: FIXED_SESSION_PRICE_DZD
    });
  }

  // سجل مدفوعات الأستاذ فقط.
  if (path === "/api/teacher/payments" && request.method === "GET") {
    const { results } = await env.DB.prepare(`
      SELECT
        b.id AS booking_id,
        b.session_date,
        b.payment_status,
        b.paid_at,
        b.created_at,
        s.first_name,
        s.last_name,
        g.name AS group_name,
        g.price_dzd
      FROM bookings b
      JOIN students s ON s.id = b.student_id
      JOIN groups g ON g.id = b.group_id
      WHERE g.teacher_id = ? AND b.status != 'cancelled'
      ORDER BY COALESCE(b.paid_at, b.created_at) DESC
      LIMIT 500
    `).bind(teacherAuth.id).all();
    return json({ payments: results });
  }

  // ==========================================
  // لوحة الأستاذ: تأكيد دفع حصة
  //
  // POST /api/teacher/bookings/BOOKING_ID/pay
  // ==========================================

  const paymentMatch = path.match(
    /^\/api\/teacher\/bookings\/([^/]+)\/pay$/
  );

  if (
    paymentMatch &&
    request.method === "POST"
  ) {
    const bookingId = paymentMatch[1];

    // التأكد من أن الحجز تابع لأحد أفواج الأستاذ
    const booking = await env.DB.prepare(`
      SELECT
        b.id,
        b.payment_status,
        b.status,
        b.session_date,
        s.first_name,
        s.last_name,
        g.name AS group_name,
        g.price_dzd,
        g.teacher_id
      FROM bookings b
      JOIN students s ON s.id = b.student_id
      JOIN groups g ON g.id = b.group_id
      WHERE b.id = ?
        AND g.teacher_id = ?
      LIMIT 1
    `).bind(
      bookingId,
      teacherAuth.id
    ).first();

    if (!booking) {
      return json({
        error: "الحجز غير موجود."
      }, 404);
    }

    if (booking.status === "cancelled") {
      return json({
        error: "لا يمكن تسجيل دفع حجز ملغى."
      }, 400);
    }

    if (booking.payment_status === "paid") {
      return json({
        error: "تم تسجيل دفع هذه الحصة من قبل."
      }, 409);
    }

    // تحديث الدفع بشرط أنه لم يُسجل سابقاً
    const result = await env.DB.prepare(`
      UPDATE bookings
      SET
        payment_status = 'paid',
        paid_at = datetime('now')
      WHERE id = ?
        AND payment_status = 'unpaid'
        AND status != 'cancelled'
    `).bind(bookingId).run();

    if (!result.meta || result.meta.changes !== 1) {
      return json({
        error: "تعذر تأكيد الدفع. ربما تم تسجيله مسبقاً."
      }, 409);
    }

    return json({
      message: "تم تأكيد الدفع بنجاح.",
      payment: {
        booking_id: bookingId,
        student_name:
          `${booking.first_name} ${booking.last_name}`,
        group_name: booking.group_name,
        session_date: booking.session_date,
        amount_dzd: Number(booking.price_dzd || FIXED_SESSION_PRICE_DZD),
        payment_status: "paid"
      }
    });
  }

  // ==========================================
  // استقبال طلب تسجيل تلميذ (لا يتم إنشاء حساب أو جلسة قبل الموافقة)
  // ==========================================
  if (path === "/api/students" && request.method === "POST") {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: "بيانات JSON غير صالحة." }, 400); }
    const firstName = String(body.first_name || "").normalize("NFKC").trim().replace(/\s+/g, " ");
    const lastName = String(body.last_name || "").normalize("NFKC").trim().replace(/\s+/g, " ");
    const age = Number(body.age);
    if (!firstName || !lastName || firstName.length > 40 || lastName.length > 40 || !Number.isInteger(age) || age < 15 || age > 18) {
      return json({ error: "أدخل الاسم واللقب، ويجب أن يكون العمر بين 15 و18 سنة." }, 400);
    }
    const normalizedName = `${firstName} ${lastName}`.normalize("NFKC").toLocaleLowerCase("ar").replace(/\s+/g, " ").trim();
    // فحص الحسابات الموجودة بتطبيع مطابق للتطبيع المستخدم في الطلبات الجديدة.
    // هذا يغطي المسافات المتكررة وأشكال Unicode التي لا يعالجها SQLite lower/trim وحدهما.
    const existingStudents = await env.DB.prepare(`SELECT id, first_name, last_name FROM students`).all();
    const duplicateStudent = (existingStudents.results || []).some(student => {
      const storedName = `${student.first_name || ""} ${student.last_name || ""}`
        .normalize("NFKC").toLocaleLowerCase("ar").replace(/\s+/g, " ").trim();
      return storedName === normalizedName;
    });
    if (duplicateStudent) return json({ error: "يوجد تلميذ مسجل بهذا الاسم واللقب مسبقاً." }, 409);
    const requestId = crypto.randomUUID();
    const requestToken = `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO student_name_registry (normalized_name, owner_type, owner_id) VALUES (?, 'request', ?)`)
          .bind(normalizedName, requestId),
        env.DB.prepare(`INSERT INTO student_registration_requests (id, first_name, last_name, age, normalized_name, token_hash) VALUES (?, ?, ?, ?, ?, ?)`)
          .bind(requestId, firstName, lastName, age, normalizedName, await sha256(requestToken))
      ]);
    } catch (error) {
      return json({ error: "هذا الاسم واللقب مسجلان بالفعل أو يوجد طلب سابق قيد المراجعة." }, 409);
    }
    return json({
      request: { id: requestId, first_name: firstName, last_name: lastName, age, status: "pending" },
      request_token: requestToken,
      status: "pending",
      message: "تم إرسال طلبك بنجاح. حسابك قيد مراجعة الإدارة."
    }, 201);
  }

  // ==========================================
  // بيانات التلميذ الحالي
  // ==========================================

  if (
    path === "/api/me" &&
    request.method === "GET"
  ) {
    const student = await authenticatedStudent(request, env);

    if (!student) {
      return json({
        error: "يلزم تسجيل الدخول."
      }, 401);
    }

    return json({ student });
  }

  // إشعارات التلميذ (داخل المنصة).
  if (path === "/api/notifications" && request.method === "GET") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    const { results } = await env.DB.prepare(`
      SELECT id, title, message, created_at
      FROM notifications
      WHERE audience = 'all' OR (audience = 'student' AND student_id = ?)
      ORDER BY created_at DESC LIMIT 50
    `).bind(student.id).all();
    return json({ notifications: results });
  }

  // ==========================================
  // حجوزات التلميذ
  // ==========================================

  if (
    path === "/api/bookings/daily-limit" &&
    request.method === "GET"
  ) {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);

    const now = localNow();
    const localDate = `${now.year}-${now.month}-${now.day}`;
    const row = await env.DB.prepare(`
      SELECT COUNT(*) AS registration_count
      FROM bookings
      WHERE student_id = ? AND registered_on = ?
    `).bind(student.id, localDate).first();
    const used = Number(row?.registration_count || 0);
    return json({
      limit: 3,
      used,
      remaining: Math.max(0, 3 - used),
      local_date: localDate,
      timezone: "Africa/Algiers"
    });
  }

  if (
    path === "/api/bookings" &&
    request.method === "GET"
  ) {
    const student = await authenticatedStudent(request, env);

    if (!student) {
      return json({
        error: "يلزم تسجيل الدخول."
      }, 401);
    }

    const { results } = await env.DB.prepare(`
      SELECT
        b.id,
        b.session_date,
        b.status,
        b.payment_status,
        b.paid_at,
        b.created_at,
        g.name AS group_name,
        g.weekday,
        g.start_time,
        g.end_time,
        g.price_dzd,
        t.name AS teacher_name
      FROM bookings b
      JOIN groups g ON g.id = b.group_id
      JOIN teachers t ON t.id = g.teacher_id
      WHERE b.student_id = ?
      ORDER BY b.session_date, g.start_time
    `).bind(student.id).all();

    return json({ bookings: results });
  }

  // ==========================================
  // تسجيل التلميذ في فوج
  // ==========================================

  if (
    path === "/api/bookings" &&
    request.method === "POST"
  ) {
    const student = await authenticatedStudent(request, env);

    if (!student) {
      return json({
        error: "يلزم تسجيل الدخول."
      }, 401);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        error: "بيانات JSON غير صالحة."
      }, 400);
    }

    const groupId = Number(body.group_id);
    const sessionDate = String(body.session_date || "");

    if (!Number.isInteger(groupId) || !sessionDate) {
      return json({
        error: "حدد الفوج وتاريخ الحصة."
      }, 400);
    }

    const group = await env.DB.prepare(`
      SELECT
        id,
        weekday,
        start_time,
        end_time,
        price_dzd
      FROM groups
      WHERE id = ?
        AND active = 1
    `).bind(groupId).first();

    if (!group) {
      return json({
        error: "الفوج غير موجود أو غير متاح."
      }, 404);
    }

    const weekday = dateWeekday(sessionDate);

    const expectedWeekday =
      group.weekday === "friday" ? 5 :
      group.weekday === "saturday" ? 6 : -1;

    if (weekday !== expectedWeekday) {
      return json({
        error: "تاريخ الحصة لا يطابق يوم الفوج."
      }, 400);
    }

    const now = localNow();

    if (!registrationWindowIsOpen(now)) {
      return json({
        error: "التسجيل متاح يومي الجمعة والسبت من 07:30 إلى 16:00 بتوقيت الجزائر."
      }, 403);
    }

    const today = `${now.year}-${now.month}-${now.day}`;

    if (sessionDate < today) {
      return json({
        error: "لا يمكن التسجيل في حصة انتهى موعدها."
      }, 400);
    }

    if (sessionDate === today) {
      const nowMinutes =
        Number(now.hour) * 60 +
        Number(now.minute);

      const startMinutes =
        Number(group.start_time.slice(0, 2)) * 60 +
        Number(group.start_time.slice(3, 5));

      if (startMinutes <= nowMinutes) {
        return json({
          error: "بدأت هذه الحصة أو انتهى موعدها."
        }, 400);
      }
    }

    const bookingId = crypto.randomUUID();
    const localDate = `${now.year}-${now.month}-${now.day}`;

    // One atomic INSERT ... SELECT enforces the daily cap in D1 itself.
    // Concurrent requests are serialized by SQLite; duplicates never count.
    const result = await env.DB.prepare(`
      INSERT INTO bookings (id, student_id, group_id, session_date, registered_on)
      SELECT ?, ?, ?, ?, ?
      WHERE (
        SELECT COUNT(*) FROM bookings
        WHERE student_id = ? AND registered_on = ?
      ) < 3
      AND NOT EXISTS (
        SELECT 1 FROM bookings
        WHERE student_id = ? AND group_id = ? AND session_date = ?
      )
    `).bind(
      bookingId, student.id, groupId, sessionDate, localDate,
      student.id, localDate, student.id, groupId, sessionDate
    ).run();

    if (Number(result?.meta?.changes || 0) !== 1) {
      const existing = await env.DB.prepare(`
        SELECT id FROM bookings
        WHERE student_id = ? AND group_id = ? AND session_date = ?
      `).bind(student.id, groupId, sessionDate).first();

      if (existing) {
        return json({ error: "أنت مسجل بالفعل في هذا الفوج لهذه الحصة." }, 409);
      }

      const usage = await env.DB.prepare(`
        SELECT COUNT(*) AS registration_count FROM bookings
        WHERE student_id = ? AND registered_on = ?
      `).bind(student.id, localDate).first();
      const used = Number(usage?.registration_count || 0);
      return json({
        error: "وصلت إلى الحد اليومي: يمكنك التسجيل في 3 أفواج فقط في اليوم الواحد.",
        limit: 3, used, remaining: Math.max(0, 3 - used), local_date: localDate
      }, 429);
    }

    return json({
      message: "تم تسجيلك بنجاح.",
      booking_id: bookingId,
      limit: 3,
      remaining: Math.max(0, 3 - Number((await env.DB.prepare(`
        SELECT COUNT(*) AS registration_count FROM bookings
        WHERE student_id = ? AND registered_on = ?
      `).bind(student.id, localDate).first())?.registration_count || 0))
    }, 201);
  }

  return json({
    error: "المسار غير موجود."
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return withCors(await handle(request, env), request, env);
    } catch (error) {
      console.error("API error", error);
      return withCors(json({ error: "حدث خطأ داخلي. حاول لاحقاً." }, 500), request, env);
    }
  },
  async scheduled(controller, env, ctx) {
    await deliverUpcomingLessonReminders(env);
  }
};
