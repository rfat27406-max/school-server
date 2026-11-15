-- Web Push subscriptions and one-time lesson reminder tracking.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_student
  ON push_subscriptions(student_id);

ALTER TABLE bookings ADD COLUMN reminder_sent_at TEXT;
CREATE INDEX IF NOT EXISTS idx_bookings_reminder_due
  ON bookings(session_date, reminder_sent_at, status);
