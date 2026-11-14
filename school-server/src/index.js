const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
  const allowOrigin = allowed.includes(origin) ? origin : (allowed.length === 0 ? "*" : "null");
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
  for (const [key, value] of Object.entries(corsHeaders(request, env))) headers.set(key, value);
  return new Response(response.body, { status: response.status, headers });
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
  return Object.fromEntries(parts.filter(p => p.type !== "literal").map(p => [p.type, p.value]));
}

function dateWeekday(dateString) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateString)) return null;
  const d = new Date(`${dateString}T12:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== dateString) return null;
  return d.getUTCDay(); // Friday=5, Saturday=6
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bearer(request) {
  const header = request.headers.get("Authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function authenticatedStudent(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(`
    SELECT s.id, s.first_name, s.last_name, s.age
    FROM student_sessions ss
    JOIN students s ON s.id = ss.student_id
    WHERE ss.token_hash = ? AND ss.revoked_at IS NULL
      AND (ss.expires_at IS NULL OR ss.expires_at > datetime('now'))
    LIMIT 1
  `).bind(tokenHash).first();
}

function registrationWindowIsOpen(now) {
  const allowedDay = now.weekday === "Friday" || now.weekday === "Saturday";
  const minutes = Number(now.hour) * 60 + Number(now.minute);
  return allowedDay && minutes >= 450 && minutes < 960;
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });
  if (path === "/api/health" && request.method === "GET") {
    return json({ ok: true, service: "school-server", timezone: "Africa/Algiers" });
  }

  if (path === "/api/teachers" && request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, name, subject, education_level FROM teachers WHERE active = 1 ORDER BY name"
    ).all();
    return json({ teachers: results });
  }

  if (path === "/api/groups" && request.method === "GET") {
    const { results } = await env.DB.prepare(`
      SELECT id, teacher_id, name, weekday, start_time, end_time, price_dzd, active
      FROM groups WHERE active = 1 ORDER BY weekday, start_time
    `).all();
    return json({ groups: results, capacity: "unlimited" });
  }

  if (path === "/api/students" && request.method === "POST") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "بيانات JSON غير صالحة." }, 400); }
    const firstName = String(body.first_name || "").trim();
    const lastName = String(body.last_name || "").trim();
    const age = Number(body.age);
    if (!firstName || !lastName || firstName.length > 40 || lastName.length > 40 ||
        !Number.isInteger(age) || age < 15 || age > 18) {
      return json({ error: "أدخل الاسم واللقب، ويجب أن يكون العمر بين 15 و18 سنة." }, 400);
    }

    const studentId = crypto.randomUUID();
    const token = `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
    const tokenHash = await sha256(token);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO students (id, first_name, last_name, age) VALUES (?, ?, ?, ?)")
        .bind(studentId, firstName, lastName, age),
      env.DB.prepare("INSERT INTO student_sessions (id, student_id, token_hash) VALUES (?, ?, ?)")
        .bind(crypto.randomUUID(), studentId, tokenHash)
    ]);
    return json({
      student: { id: studentId, first_name: firstName, last_name: lastName, age },
      access_token: token,
      token_type: "Bearer",
      note: "احتفظ برمز الدخول. استعادة الحساب تحتاج إضافة وسيلة تحقق في مرحلة لاحقة."
    }, 201);
  }

  if (path === "/api/me" && request.method === "GET") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    return json({ student });
  }

  if (path === "/api/bookings" && request.method === "GET") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    const { results } = await env.DB.prepare(`
      SELECT b.id, b.session_date, b.status, b.payment_status, b.created_at,
             g.name AS group_name, g.weekday, g.start_time, g.end_time, g.price_dzd,
             t.name AS teacher_name
      FROM bookings b
      JOIN groups g ON g.id = b.group_id
      JOIN teachers t ON t.id = g.teacher_id
      WHERE b.student_id = ?
      ORDER BY b.session_date, g.start_time
    `).bind(student.id).all();
    return json({ bookings: results });
  }

  if (path === "/api/bookings" && request.method === "POST") {
    const student = await authenticatedStudent(request, env);
    if (!student) return json({ error: "يلزم تسجيل الدخول." }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ error: "بيانات JSON غير صالحة." }, 400); }
    const groupId = Number(body.group_id);
    const sessionDate = String(body.session_date || "");
    if (!Number.isInteger(groupId) || !sessionDate) return json({ error: "حدد الفوج وتاريخ الحصة." }, 400);

    const group = await env.DB.prepare(
      "SELECT id, weekday, start_time, end_time, price_dzd FROM groups WHERE id = ? AND active = 1"
    ).bind(groupId).first();
    if (!group) return json({ error: "الفوج غير موجود أو غير متاح." }, 404);

    const weekday = dateWeekday(sessionDate);
    const expectedWeekday = group.weekday === "friday" ? 5 : group.weekday === "saturday" ? 6 : -1;
    if (weekday !== expectedWeekday) return json({ error: "تاريخ الحصة لا يطابق يوم الفوج." }, 400);

    const now = localNow();
    if (!registrationWindowIsOpen(now)) {
      return json({ error: "التسجيل متاح يومي الجمعة والسبت من 07:30 إلى 16:00 بتوقيت الجزائر." }, 403);
    }
    const today = `${now.year}-${now.month}-${now.day}`;
    if (sessionDate < today) return json({ error: "لا يمكن التسجيل في حصة انتهى موعدها." }, 400);
    if (sessionDate === today) {
      const nowMinutes = Number(now.hour) * 60 + Number(now.minute);
      const startMinutes = Number(group.start_time.slice(0, 2)) * 60 + Number(group.start_time.slice(3, 5));
      if (startMinutes <= nowMinutes) return json({ error: "بدأت هذه الحصة أو انتهى موعدها." }, 400);
    }

    const bookingId = crypto.randomUUID();
    try {
      await env.DB.prepare(`
        INSERT INTO bookings (id, student_id, group_id, session_date)
        VALUES (?, ?, ?, ?)
      `).bind(bookingId, student.id, groupId, sessionDate).run();
    } catch (error) {
      const existing = await env.DB.prepare(
        "SELECT id FROM bookings WHERE student_id = ? AND group_id = ? AND session_date = ?"
      ).bind(student.id, groupId, sessionDate).first();
      if (existing) return json({ error: "أنت مسجل بالفعل في هذا الفوج لهذه الحصة." }, 409);
      throw error;
    }
    return json({ message: "تم تسجيلك بنجاح.", booking_id: bookingId }, 201);
  }

  return json({ error: "المسار غير موجود." }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return withCors(await handle(request, env), request, env);
    } catch (error) {
      console.error("API error", error);
      return withCors(json({ error: "حدث خطأ داخلي. حاول لاحقاً." }, 500), request, env);
    }
  }
};
