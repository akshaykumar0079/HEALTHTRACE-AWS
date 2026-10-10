#!/usr/bin/env bash
# Start the whole HEALTHTRACE demo in one terminal:
#   log generator + backend (API, WebSocket, alerts/email) + dashboard.
# Usage (from the HEALTHTRACE folder):   ./start.sh
# Then open http://localhost:5173 . Press Ctrl+C here to stop everything.
set -u
cd "$(dirname "$0")"

if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
else
  echo "No .venv found. Create it first: python3 -m venv .venv && . .venv/bin/activate && pip install -e 'backend[dev]'"
  exit 1
fi

pids=""
cleanup() {
  echo ""
  echo "Stopping HEALTHTRACE..."
  trap - INT TERM
  for pid in $pids; do kill "$pid" 2>/dev/null; done
  # npm starts vite as a grandchild: stop everything in this process group too.
  kill 0 2>/dev/null
  exit 0
}
trap cleanup INT TERM

mkdir -p data/logs
if [ ! -s data/logs/app.log ]; then
  echo "First run: seeding 2 hours of normal history (about a minute)..."
  python -m generator.generate --backfill-hours 2
fi

python -m generator.generate --rate 30 > data/generator.log 2>&1 &
pids="$pids $!"

(cd backend && exec uvicorn app.main:app --port 8010) &
pids="$pids $!"

(cd frontend && exec npm run dev -- --port 5173 --strictPort) &
pids="$pids $!"

sleep 4
echo ""
echo "HEALTHTRACE is running:  http://localhost:5173"
echo "Trigger an alert: open the dashboard, press Cmd+K, choose 'Bulk PHI access' (CRITICAL)."
echo "Press Ctrl+C to stop."
wait
