-- 0008: allow all weekdays, preserve every booking/payment field, and add reminder preference.
-- The live database already has archived_at and price_dzd columns from the previous rollout.
CREATE TABLE groups_new (
  id INTEGER PRIMARY KEY,
  teacher_id TEXT NOT NULL REFERENCES teachers(id),
  name TEXT NOT NULL,
  weekday TEXT NOT NULL CHECK (weekday IN ('sunday','monday','tuesday','wednesday','thursday','friday','saturday')),
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  price_dzd INTEGER NOT NULL DEFAULT 300 CHECK (price_dzd >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (start_time < end_time)
);
INSERT INTO groups_new (id, teacher_id, name, weekday, start_time, end_time, price_dzd, active, created_at)
SELECT id, teacher_id, name, weekday, start_time, end_time, price_dzd, active, created_at FROM groups;

CREATE TABLE bookings_new (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id),
  group_id INTEGER NOT NULL REFERENCES groups_new(id),
  session_date TEXT NOT NULL,
  registered_on TEXT,
  reminder_sent_at TEXT,
  archived_at TEXT,
  price_dzd INTEGER NOT NULL DEFAULT 300 CHECK (price_dzd >= 0),
  status TEXT NOT NULL DEFAULT 'registered' CHECK (status IN ('registered','cancelled','attended','absent')),
  payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','paid')),
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(student_id, group_id, session_date)
);
INSERT INTO bookings_new (id, student_id, group_id, session_date, registered_on, reminder_sent_at, archived_at, price_dzd, status, payment_status, paid_at, created_at)
SELECT id, student_id, group_id, session_date, registered_on, reminder_sent_at, archived_at, price_dzd, status, payment_status, paid_at, created_at FROM bookings;

DROP TABLE bookings;
DROP TABLE groups;
ALTER TABLE groups_new RENAME TO groups;
ALTER TABLE bookings_new RENAME TO bookings;
CREATE INDEX idx_bookings_student ON bookings(student_id, session_date);
CREATE INDEX idx_bookings_group_date ON bookings(group_id, session_date);
CREATE INDEX idx_bookings_student_registered_on ON bookings(student_id, registered_on);
CREATE INDEX idx_bookings_reminder_due ON bookings(session_date, reminder_sent_at, status);
CREATE INDEX idx_bookings_archive ON bookings(archived_at, session_date);

ALTER TABLE students ADD COLUMN reminder_minutes INTEGER NOT NULL DEFAULT 30 CHECK (reminder_minutes IN (5,15,30));
