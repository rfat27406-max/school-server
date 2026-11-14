-- Apply once to the existing Cloudflare D1 database.
-- Three successful group registrations per student account per Algeria-local day.
-- Account creation is intentionally not limited.
ALTER TABLE bookings ADD COLUMN registered_on TEXT;
CREATE INDEX IF NOT EXISTS idx_bookings_student_registered_on
  ON bookings(student_id, registered_on);
