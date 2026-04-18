#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# DriftGuard — One-Click Setup
# Human-State Drift Detection for Cybersecurity
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/user/DriftGuard/main/setup.sh | bash
#   — or —
#   git clone https://github.com/user/DriftGuard.git && cd DriftGuard && ./setup.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[DriftGuard]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          DriftGuard — One-Click Setup                ║${NC}"
echo -e "${BOLD}║  Human-State Drift Detection for Cybersecurity       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect OS ──────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux*)   PLATFORM="linux" ;;
  Darwin*)  PLATFORM="mac" ;;
  *)        fail "Unsupported OS: $OS. DriftGuard supports macOS and Linux." ;;
esac
info "Detected platform: $PLATFORM"

# ─── Choose mode ────────────────────────────────────────────
MODE="${1:-auto}"

if [ "$MODE" = "docker" ]; then
  info "Docker mode selected"
elif [ "$MODE" = "local" ]; then
  info "Local development mode selected"
elif [ "$MODE" = "auto" ]; then
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    MODE="docker"
    info "Docker detected — using Docker mode (pass 'local' for dev mode)"
  else
    MODE="local"
    info "Docker not found — using local development mode"
  fi
fi

# ═════════════════════════════════════════════════════════════
# DOCKER MODE — one command, full stack
# ═════════════════════════════════════════════════════════════
if [ "$MODE" = "docker" ]; then
  command -v docker &>/dev/null || fail "Docker is required. Install from https://docs.docker.com/get-docker/"
  
  info "Starting DriftGuard with Docker Compose..."
  
  # Generate secret key if not set
  if [ ! -f .env ]; then
    echo "SECRET_KEY=$(openssl rand -hex 32)" > .env
    ok "Generated .env with secret key"
  fi
  
  docker compose up --build -d
  
  echo ""
  echo -e "${GREEN}${BOLD}DriftGuard is running!${NC}"
  echo ""
  echo -e "  ${BOLD}Frontend:${NC}     http://localhost"
  echo -e "  ${BOLD}Backend API:${NC}  http://localhost:8000"
  echo -e "  ${BOLD}API Docs:${NC}     http://localhost:8000/docs"
  echo -e "  ${BOLD}Grafana:${NC}      http://localhost:3001  (admin / driftguard)"
  echo -e "  ${BOLD}Prometheus:${NC}   http://localhost:9090"
  echo ""
  echo -e "  Stop:  ${CYAN}docker compose down${NC}"
  echo -e "  Logs:  ${CYAN}docker compose logs -f${NC}"
  echo ""
  exit 0
fi

# ═════════════════════════════════════════════════════════════
# LOCAL MODE — Python venv + Node.js dev servers
# ═════════════════════════════════════════════════════════════

# ─── Check prerequisites ────────────────────────────────────
info "Checking prerequisites..."

PYTHON=""
for cmd in python3.12 python3.11 python3; do
  if command -v "$cmd" &>/dev/null; then
    PY_VERSION=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
      PYTHON="$cmd"
      break
    fi
  fi
done
[ -z "$PYTHON" ] && fail "Python 3.10+ is required. Install from https://python.org"
ok "Python: $($PYTHON --version)"

NODE=""
if command -v node &>/dev/null; then
  NODE_VERSION=$(node --version | grep -oE '[0-9]+' | head -1)
  if [ "$NODE_VERSION" -ge 18 ]; then
    NODE="node"
  fi
fi
[ -z "$NODE" ] && fail "Node.js 18+ is required. Install from https://nodejs.org"
ok "Node.js: $(node --version)"

command -v npm &>/dev/null || fail "npm is required (comes with Node.js)"
ok "npm: $(npm --version)"

# ─── Backend setup ──────────────────────────────────────────
info "Setting up backend..."

cd backend

if [ ! -d "venv" ]; then
  $PYTHON -m venv venv
  ok "Created Python virtual environment"
fi

source venv/bin/activate

pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "Installed Python dependencies"

cd ..

# ─── Frontend setup ─────────────────────────────────────────
info "Setting up frontend..."

cd frontend

if [ ! -d "node_modules" ]; then
  npm install --silent 2>/dev/null
  ok "Installed Node.js dependencies"
else
  ok "Node.js dependencies already installed"
fi

cd ..

# ─── Generate .env if needed ────────────────────────────────
if [ ! -f .env ]; then
  cat > .env << 'EOF'
SECRET_KEY=dev-secret-change-in-production
ENVIRONMENT=development
DATABASE_URL=sqlite+aiosqlite:///./driftguard.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
EOF
  ok "Created .env file"
fi

# ─── Start services ────────────────────────────────────────
info "Starting DriftGuard..."

# Start backend
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000 &
BACKEND_PID=$!
cd ..

# Wait for backend
sleep 3
if kill -0 $BACKEND_PID 2>/dev/null; then
  ok "Backend started (PID: $BACKEND_PID)"
else
  fail "Backend failed to start. Check logs above."
fi

# Start frontend
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

sleep 2
if kill -0 $FRONTEND_PID 2>/dev/null; then
  ok "Frontend started (PID: $FRONTEND_PID)"
else
  warn "Frontend may have failed. Check logs above."
fi

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║          DriftGuard is running!                      ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Frontend:${NC}     http://localhost:3000"
echo -e "  ${BOLD}Backend API:${NC}  http://localhost:8000"
echo -e "  ${BOLD}API Docs:${NC}     http://localhost:8000/docs"
echo ""
echo -e "  Stop:  ${CYAN}kill $BACKEND_PID $FRONTEND_PID${NC}"
echo ""
echo -e "  ${YELLOW}\"Every cybersecurity breach has a human-state precursor."
echo -e "   Current tools catch the breach. We catch the precursor.\"${NC}"
echo ""

# Keep running
wait
