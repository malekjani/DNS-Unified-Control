#!/bin/sh
set -eu
cd /opt/dns-unified-control
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.fieldcheck
