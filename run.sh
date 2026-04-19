#!/bin/bash

# ═══════════════════════════════════════════════════════
#  NetGuard — One-click startup script
#  Place this file in:  EECS_592_Capstone/
#  Run with:            bash run.sh
# ═══════════════════════════════════════════════════════

# ── Colors ─────────────────────────────────────────────
GREEN='\033[0;32m'
GOLD='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${GOLD}  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ${NC}"
echo -e "${GOLD}  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗${NC}"
echo -e "${GOLD}  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║${NC}"
echo -e "${GOLD}  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║${NC}"
echo -e "${GOLD}  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝${NC}"
echo -e "${GOLD}  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ${NC}"
echo ""
echo -e "${BLUE}  Network Intelligence Platform — Starting up...${NC}"
echo ""

# ── Paths ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv/bin/python3"
BACKEND="$SCRIPT_DIR/src/Backend"
FRONTEND="$SCRIPT_DIR/src/Frontend"
FRONTEND_PORT=8080
DASHBOARD_URL="http://localhost:${FRONTEND_PORT}/dashboard.html"

# ── Cleanup on Ctrl+C — kills ALL child processes ──────
FRONTEND_PID=""
BACKEND_PID=""

cleanup() {
  echo ""
  echo -e "${GOLD}  Shutting down NetGuard...${NC}"
  if [ ! -z "$FRONTEND_PID" ]; then
    kill "$FRONTEND_PID" 2>/dev/null
    echo -e "${GREEN}  ✓ Frontend server stopped${NC}"
  fi
  if [ ! -z "$BACKEND_PID" ]; then
    sudo kill "$BACKEND_PID" 2>/dev/null
    echo -e "${GREEN}  ✓ Backend API stopped${NC}"
  fi
  echo -e "${GOLD}  Goodbye.${NC}"
  echo ""
  exit 0
}
trap cleanup SIGINT SIGTERM

# ── Check / create venv ─────────────────────────────────
if [ ! -f "$VENV" ]; then
  echo -e "${RED}  ✗ Virtual environment not found${NC}"
  echo -e "${GOLD}  Creating venv...${NC}"
  python3 -m venv "$SCRIPT_DIR/venv"
  echo -e "${GREEN}  ✓ venv created${NC}"
fi

# ── Install dependencies ────────────────────────────────
source "$SCRIPT_DIR/venv/bin/activate"
echo -e "${BLUE}  → Checking dependencies...${NC}"
pip install flask flask-cors boto3 scapy pyyaml requests PyJWT bcrypt -q
echo -e "${GREEN}  ✓ Dependencies ready${NC}"

# ── AWS Credentials ─────────────────────────────────────
# Option A: auto-loads if already in ~/.zshrc
# Option B: paste your keys directly between the quotes:
export AWS_ACCESS_KEY_ID="INSERT HERE"
export AWS_SECRET_ACCESS_KEY="INSERT HERE"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-2}"
export LOG_BUCKET="${LOG_BUCKET:-monitoring-pcap-storage}"

# ── Auth & Audit env vars ────────────────────────────────
# JWT_SECRET: must be a long random string in production.
# Generate one with:  python3 -c "import secrets; print(secrets.token_hex(32))"
export JWT_SECRET="${JWT_SECRET:-CHANGE_ME_BEFORE_PRODUCTION_use_token_hex_32}"
export DYNAMO_AUDIT_TABLE="${DYNAMO_AUDIT_TABLE:-AuditLogs}"
export DYNAMO_USERS_TABLE="${DYNAMO_USERS_TABLE:-NetGuardUsers}"
export ARCHIVE_BUCKET="${ARCHIVE_BUCKET:-audit-logs-archive}"

if [ -z "$AWS_ACCESS_KEY_ID" ]; then
  echo ""
  echo -e "${GOLD}  ⚠  AWS credentials not set — AWS panels will show offline.${NC}"
  echo -e "${GOLD}     Add keys to ~/.zshrc or paste them into run.sh${NC}"
  echo ""
else
  echo -e "${GREEN}  ✓ AWS credentials loaded${NC}"
fi

# ── Kill anything already on frontend port ──────────────
lsof -ti tcp:$FRONTEND_PORT | xargs kill -9 2>/dev/null

# ── Start frontend file server in background ────────────
echo -e "${BLUE}  → Starting frontend server on port ${FRONTEND_PORT}...${NC}"
python3 -m http.server $FRONTEND_PORT --directory "$FRONTEND" &>/dev/null &
FRONTEND_PID=$!
echo -e "${GREEN}  ✓ Frontend server started (PID $FRONTEND_PID)${NC}"

# ── Start backend API with sudo in background ───────────
echo -e "${BLUE}  → Starting backend API + packet capture...${NC}"
sudo \
  AWS_ACCESS_KEY_ID="INSERT HERE" \
  AWS_SECRET_ACCESS_KEY="INSERT HERE" \
  AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
  LOG_BUCKET="$LOG_BUCKET" \
  JWT_SECRET="$JWT_SECRET" \
  DYNAMO_AUDIT_TABLE="$DYNAMO_AUDIT_TABLE" \
  DYNAMO_USERS_TABLE="$DYNAMO_USERS_TABLE" \
  ARCHIVE_BUCKET="$ARCHIVE_BUCKET" \
  "$VENV" "$BACKEND/app.py" &
BACKEND_PID=$!

# ── Wait for API to be ready then open browser ──────────
echo -e "${BLUE}  → Waiting for API to be ready...${NC}"
for i in {1..15}; do
  if curl -s http://localhost:5000/api/stats > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ API is ready${NC}"
    break
  fi
  sleep 1
done

# ── Open browser ────────────────────────────────────────
echo -e "${BLUE}  → Opening dashboard...${NC}"
open "$DASHBOARD_URL"

# ── Print summary ───────────────────────────────────────
echo ""
echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}  ║           NetGuard is LIVE                       ║${NC}"
echo -e "${GREEN}  ╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}  ║  🌐 Dashboard → ${DASHBOARD_URL}   ║${NC}"
echo -e "${GREEN}  ║  📡 API       → http://localhost:5000            ║${NC}"
echo -e "${GREEN}  ║  ☁️  AWS       → s3://${LOG_BUCKET}   ║${NC}"
echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}  Packets are being captured live. Press Ctrl+C to stop.${NC}"
echo ""

# ── Keep script alive (wait for Ctrl+C) ────────────────
wait $BACKEND_PID
