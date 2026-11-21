-- Add the archival timestamp used by the scheduled cleanup and teacher views.
ALTER TABLE bookings ADD COLUMN archived_at TEXT;
CREATE INDEX IF NOT EXISTS idx_bookings_archive ON bookings(archived_at, session_date);
