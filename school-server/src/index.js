
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

const FIXED_SESSION_PRICE_DZD = 300;
const TEACHER_ID = "teacher-boumediene";

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

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
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
  // الإدارة العامة: جميع التلاميذ
  // ==========================================

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
      SELECT id, name, subject, education_level
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
        id,
        teacher_id,
        name,
        weekday,
        start_time,
        end_time,
        price_dzd,
        active
      FROM groups
      WHERE active = 1
      ORDER BY weekday, start_time
    `).all();

    return json({
      groups: results,
      capacity: "unlimited"
    });
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
    `).bind(TEACHER_ID).all();

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
            THEN ?
            ELSE 0
          END
        ), 0) AS total_revenue

      FROM groups g
      LEFT JOIN bookings b ON b.group_id = g.id
      WHERE g.teacher_id = ?
    `).bind(
      FIXED_SESSION_PRICE_DZD,
      TEACHER_ID
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
      TEACHER_ID
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

    const bindings = [groupId, TEACHER_ID];

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
        revenue: paidCount * FIXED_SESSION_PRICE_DZD
      },
      session_price: FIXED_SESSION_PRICE_DZD
    });
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
        g.teacher_id
      FROM bookings b
      JOIN students s ON s.id = b.student_id
      JOIN groups g ON g.id = b.group_id
      WHERE b.id = ?
        AND g.teacher_id = ?
      LIMIT 1
    `).bind(
      bookingId,
      TEACHER_ID
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
        amount_dzd: FIXED_SESSION_PRICE_DZD,
        payment_status: "paid"
      }
    });
  }

  // ==========================================
  // تسجيل تلميذ جديد
  // ==========================================

  if (
    path === "/api/students" &&
    request.method === "POST"
  ) {
    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        error: "بيانات JSON غير صالحة."
      }, 400);
    }

    const firstName = String(body.first_name || "").trim();
    const lastName = String(body.last_name || "").trim();
    const age = Number(body.age);

    if (
      !firstName ||
      !lastName ||
      firstName.length > 40 ||
      lastName.length > 40 ||
      !Number.isInteger(age) ||
      age < 15 ||
      age > 18
    ) {
      return json({
        error: "أدخل الاسم واللقب، ويجب أن يكون العمر بين 15 و18 سنة."
      }, 400);
    }

    const studentId = crypto.randomUUID();

    const token =
      `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;

    const tokenHash = await sha256(token);

    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO students (
          id,
          first_name,
          last_name,
          age
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        studentId,
        firstName,
        lastName,
        age
      ),

      env.DB.prepare(`
        INSERT INTO student_sessions (
          id,
          student_id,
          token_hash
        )
        VALUES (?, ?, ?)
      `).bind(
        crypto.randomUUID(),
        studentId,
        tokenHash
      )
    ]);

    return json({
      student: {
        id: studentId,
        first_name: firstName,
        last_name: lastName,
        age
      },
      access_token: token,
      token_type: "Bearer",
      note: "احتفظ برمز الدخول. استعادة الحساب تحتاج إضافة وسيلة تحقق في مرحلة لاحقة."
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

  // ==========================================
  // حجوزات التلميذ
  // ==========================================

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

    try {
      await env.DB.prepare(`
        INSERT INTO bookings (
          id,
          student_id,
          group_id,
          session_date
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        bookingId,
        student.id,
        groupId,
        sessionDate
      ).run();

    } catch (error) {
      const existing = await env.DB.prepare(`
        SELECT id
        FROM bookings
        WHERE student_id = ?
          AND group_id = ?
          AND session_date = ?
      `).bind(
        student.id,
        groupId,
        sessionDate
      ).first();

      if (existing) {
        return json({
          error: "أنت مسجل بالفعل في هذا الفوج لهذه الحصة."
        }, 409);
      }

      throw error;
    }

    return json({
      message: "تم تسجيلك بنجاح.",
      booking_id: bookingId
    }, 201);
  }

  return json({
    error: "المسار غير موجود."
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return withCors(
        await handle(request, env),
        request,
        env
      );
    } catch (error) {
      console.error("API error", error);

      return withCors(
        json({
          error: "حدث خطأ داخلي. حاول لاحقاً."
        }, 500),
        request,
        env
      );
    }
  }
};
