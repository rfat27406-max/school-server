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
-- Reserve names of students that already exist before this feature.
INSERT OR IGNORE INTO student_name_registry (normalized_name, owner_type, owner_id)
SELECT lower(trim(first_name || ' ' || last_name)), 'student', id FROM students;
