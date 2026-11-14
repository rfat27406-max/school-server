PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS teachers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  education_level TEXT NOT NULL,
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
  status TEXT NOT NULL DEFAULT 'registered' CHECK (status IN ('registered','cancelled','attended','absent')),
  payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','paid')),
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(student_id, group_id, session_date)
);

CREATE INDEX IF NOT EXISTS idx_bookings_student ON bookings(student_id, session_date);
CREATE INDEX IF NOT EXISTS idx_bookings_group_date ON bookings(group_id, session_date);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON student_sessions(token_hash);

INSERT OR IGNORE INTO teachers (id, name, subject, education_level)
VALUES ('teacher-boumediene', 'الأستاذ بومدين', 'العلوم الطبيعية', 'الطور الثانوي');

INSERT OR IGNORE INTO groups (id, teacher_id, name, weekday, start_time, end_time, price_dzd) VALUES
(1, 'teacher-boumediene', 'الفوج الأول', 'friday', '08:00', '10:00', 300),
(2, 'teacher-boumediene', 'الفوج الثاني', 'friday', '10:00', '12:00', 300),
(3, 'teacher-boumediene', 'الفوج الثالث', 'friday', '14:00', '16:00', 300),
(4, 'teacher-boumediene', 'الفوج الرابع', 'saturday', '08:00', '10:00', 300),
(5, 'teacher-boumediene', 'الفوج الخامس', 'saturday', '10:00', '12:00', 300);
