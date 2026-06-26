#!/bin/bash
# Advertise host is set via fly secret or env var.
# fly secrets set RP_ADVERTISE_HOST=tn-redpanda.fly.dev
ADVERTISE_HOST="${RP_ADVERTISE_HOST:-localhost}"

exec /usr/bin/rpk redpanda start \
    --mode dev-container \
    --kafka-addr        PLAINTEXT://0.0.0.0:9092 \
    --advertise-kafka-addr "PLAINTEXT://${ADVERTISE_HOST}:9092" \
    --pandaproxy-addr   "http://0.0.0.0:8082" \
    --advertise-pandaproxy-addr "http://${ADVERTISE_HOST}:8082" \
    --rpc-addr          "0.0.0.0:33145" \
    --advertise-rpc-addr "${ADVERTISE_HOST}:33145"
