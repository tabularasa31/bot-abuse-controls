-- Demo-stand blocklist — empty by design (shadow mode).
--
-- The cascade computes a verdict for every request and logs it, but
-- nothing is blocked: blocking default curl/python would also block our
-- own devs, and real bots masquerade as browsers anyway. We accumulate
-- data first, decide what to block later (see the ClickUp demo-stand
-- doc, "Текущий режим: SHADOW").
--
-- To switch to active blocking, paste fp tokens here (matching what
-- /__fp reports for a given client) and reload. Per Phase 1/2 specs,
-- that's a deliberate, data-driven step off the back of analyze.py
-- HIGH-confidence candidates.

local _M = {}

_M.entries = {}

return _M
