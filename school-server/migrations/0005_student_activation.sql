-- Student activation workflow: new registrations wait for admin approval.
ALTER TABLE students ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'
  CHECK (approval_status IN ('pending','approved','rejected','locked'));
ALTER TABLE students ADD COLUMN rejection_count INTEGER NOT NULL DEFAULT 0
  CHECK (rejection_count BETWEEN 0 AND 3);
