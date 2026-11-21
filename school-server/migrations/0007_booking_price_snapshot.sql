-- Preserve the agreed group price for each booking, even after a group price changes.
ALTER TABLE bookings ADD COLUMN price_dzd INTEGER NOT NULL DEFAULT 300 CHECK (price_dzd >= 0);
UPDATE bookings
SET price_dzd = (SELECT price_dzd FROM groups WHERE groups.id = bookings.group_id)
WHERE EXISTS (SELECT 1 FROM groups WHERE groups.id = bookings.group_id);
