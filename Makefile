.PHONY: gen backfill backend frontend build test eval demo deploy

# Continuous normal traffic, polling data/control.json for demo injections.
# Run as a module (not `python generator/generate.py`) so its `from
# generator.scenarios import ...` resolves with the repo root on sys.path.
gen:
	python -m generator.generate --rate 30

# 24h of normal historical logs so every (service, hour_of_day) baseline is warm.
backfill:
	python -m generator.generate --backfill-hours 24

backend:
	cd backend && uvicorn app.main:app --reload --port 8010

frontend:
	cd frontend && npm run dev

build:
	cd frontend && npm ci && npm run build

test:
	python -m pytest backend/tests -q

# Detector vs baseline vs ablations over 10 seeds -> data/evaluation (docs/evaluation.md).
eval:
	cd backend && python -m app.evaluation --workers 3

# Backfill + generator + backend + UI in containers, on http://localhost:8080.
demo:
	docker compose up --build

deploy:
	./deploy/aws/deploy.sh
