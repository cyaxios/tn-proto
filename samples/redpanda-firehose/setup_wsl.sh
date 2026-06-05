#!/usr/bin/env bash
# Run from WSL codex:
#   wsl -d codex -- bash /mnt/c/codex/tn/tn_proto/samples/redpanda-firehose/setup_wsl.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DEMO_PROJECT="00000000-0000-0000-0000-000000000001"
TOPIC="tn.firehose.${DEMO_PROJECT}"

echo "==> Starting Redpanda"
docker compose up -d redpanda

echo "==> Waiting for Redpanda to be healthy..."
for i in $(seq 1 30); do
  if docker compose exec -T redpanda rpk cluster health 2>/dev/null | grep -q "Healthy"; then
    echo "    healthy after ${i}s"
    break
  fi
  sleep 2
done

echo "==> Creating demo firehose topic: ${TOPIC}"
docker compose exec -T redpanda rpk topic create "${TOPIC}" \
  --partitions 3 \
  --replicas 1 \
  2>/dev/null && echo "    created" || echo "    already exists"

echo "==> Starting Redpanda Console"
docker compose up -d console

echo "==> Creating venv + installing Python deps"
python3 -m venv "${SCRIPT_DIR}/.venv"
"${SCRIPT_DIR}/.venv/bin/pip" install --quiet kafka-python cryptography

echo
echo "=========================================="
echo " Redpanda ready at localhost:9092"
echo " Console:  http://localhost:8080"
echo " Topic:    ${TOPIC}"
echo "=========================================="
echo
echo "Produce:"
echo "  cd ${SCRIPT_DIR}"
echo "  .venv/bin/python demo_produce.py"
echo
echo "Consume (in a second terminal):"
echo "  .venv/bin/python demo_consume.py"
echo
