PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS teachers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  education_level TEXT NOT NULL,
  password_hash TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY,
  teacher_id TEXT NOT NULL REFERENCES teachers(id),
  name TEXT NOT NULL,
  weekday TEXT NOT NULL CHECK (weekday IN ('friday','saturday')),
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  price_dzd INTEGER NOT NULL DEFAULT 300 CHECK (price_dzd >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (start_time < end_time)
);

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  age INTEGER NOT NULL CHECK (age BETWEEN 15 AND 18),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS student_sessions (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id),
  group_id INTEGER NOT NULL REFERENCES groups(id),
  session_date TEXT NOT NULL,
  registered_on TEXT,
  reminder_sent_at TEXT,
  status TEXT NOT NULL DEFAULT 'registered' CHECK (status IN ('registered','cancelled','attended','absent')),
  payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','paid')),
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(student_id, group_id, session_date)
);

CREATE INDEX IF NOT EXISTS idx_bookings_student ON bookings(student_id, session_date);
CREATE INDEX IF NOT EXISTS idx_bookings_group_date ON bookings(group_id, session_date);
CREATE INDEX IF NOT EXISTS idx_bookings_student_registered_on ON bookings(student_id, registered_on);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON student_sessions(token_hash);

INSERT OR IGNORE INTO teachers (id, name, subject, education_level)
VALUES ('teacher-boumediene', 'الأستاذ بومدين', 'العلوم الطبيعية', 'الطور الثانوي');

INSERT OR IGNORE INTO groups (id, teacher_id, name, weekday, start_time, end_time, price_dzd) VALUES
(1, 'teacher-boumediene', 'الفوج الأول', 'friday', '08:00', '10:00', 300),
(2, 'teacher-boumediene', 'الفوج الثاني', 'friday', '10:00', '12:00', 300),
(3, 'teacher-boumediene', 'الفوج الثالث', 'friday', '14:00', '16:00', 300),
(4, 'teacher-boumediene', 'الفوج الرابع', 'saturday', '08:00', '10:00', 300),
(5, 'teacher-boumediene', 'الفوج الخامس', 'saturday', '10:00', '12:00', 300);

-- Sessions منفصلة للإدارة والأساتذة.
CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS teacher_sessions (
  id TEXT PRIMARY KEY,
  teacher_id TEXT NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_teacher_sessions_token ON teacher_sessions(token_hash);

-- إشعارات داخل المنصة. Web Push يتطلب إعداد VAPID وService Worker منفصلين.
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience IN ('all','student')),
  student_id TEXT REFERENCES students(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_student ON notifications(student_id, created_at);

CREATE TABLE IF NOT EXISTS auth_login_limits (
  ip_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  window_key TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip_hash, purpose, window_key)
);



-- Web Push device subscriptions.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_student ON push_subscriptions(student_id);
CREATE INDEX IF NOT EXISTS idx_bookings_reminder_due ON bookings(session_date, reminder_sent_at, status);

-- Approval workflow for new student registrations.
CREATE TABLE IF NOT EXISTS student_registration_requests (
  id TEXT PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  age INTEGER NOT NULL CHECK (age BETWEEN 15 AND 18),
  normalized_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  rejection_reason TEXT,
  student_id TEXT REFERENCES students(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  claimed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_student_registration_status ON student_registration_requests(status, created_at);
CREATE TABLE IF NOT EXISTS student_name_registry (
  normalized_name TEXT PRIMARY KEY,
  owner_type TEXT NOT NULL CHECK (owner_type IN ('request','student')),
  owner_id TEXT NOT NULL
);
INSERT OR IGNORE INTO student_name_registry (normalized_name, owner_type, owner_id)
SELECT lower(trim(first_name || ' ' || last_name)), 'student', id FROM students;
