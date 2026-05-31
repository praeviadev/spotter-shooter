#!/usr/bin/env bash
set -euo pipefail
AMBER='[38;5;178m'; GREEN='[38;5;71m'; RED='[38;5;160m'; NC='[0m'
printf "${AMBER}SPOTTER-SHOOTER // DEPLOYMENT SEQUENCE${NC}
"
command -v docker >/dev/null || { echo -e "${RED}Docker missing${NC}"; exit 1; }
docker info >/dev/null || { echo -e "${RED}Docker not running${NC}"; exit 1; }
[ -f .env ] || cp .env.example .env
docker compose pull --ignore-buildable
docker compose up -d --build --remove-orphans
for i in {1..90}; do docker exec spotter-api python -c "import json,urllib.request; json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/health',timeout=2))" >/dev/null 2>&1 && break || sleep 2; done
HOST=$(grep '^APP_HOST=' .env|cut -d= -f2)
echo -e "${GREEN}Spotter-Shooter online.${NC}"
echo "https://${HOST}"
echo "Open the URL above to begin setup"
