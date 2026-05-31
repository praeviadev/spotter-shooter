# SPOTTER-SHOOTER

AI-assisted threat hunting platform for professional security operators.

## Deploy

```bash
./deploy.sh
```

Routes: `/`, `/operations.html`, `/admin/agents`, `/api/health`, `/docs`.

Includes 11 built-in agents plus a DB-backed custom agent framework.

## SSH forwarding demo mode

This deployment is intentionally bound to server loopback only, not public DNS.

```bash
ssh -L 8097:127.0.0.1:8097 USER@134.199.206.236
```

Then open `http://127.0.0.1:8097`.
