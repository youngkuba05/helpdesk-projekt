# LAB7 — Konfiguracja bezpieczeństwa środowiska AWS

Moduł Terraform wdraża warstwę ochrony obwodowej i wykrywania włamań dla systemu TicketDesk:

1. **WAF (AWS WAF v2):** reguły zarządzane (`CommonRuleSet`, `KnownBadInputs`, `SQLi`, `AmazonIpReputationList`) oraz reguły Rate-Based (100 req/5 min dla `/login`, 1000 req/5 min globalnie) z logowaniem do CloudWatch (`aws-waf-logs-ticketdesk`).
2. **CDN i AntyDDoS (Amazon CloudFront + AWS Shield Standard):** terminacja ruchu na krawędzi sieci, wymuszenie HTTPS/TLS 1.2+, buforowanie wyłącznie `/static/*`, wyłączone cache'owanie widoków dynamicznych oraz nagłówek `X-Origin-Verify` chroniący ALB przed ruchem omijającym CloudFront.
3. **IPS/IDS (Amazon GuardDuty + VPC Flow Logs):** detekcja anomalii sieciowych i prób włamań w `ticketdesk-vpc`, pełne logi przepływów sieciowych w `/aws/vpc/ticketdesk-flow-logs` oraz alarm CloudWatch dla skoków blokad WAF.

## Wymagane zmiany po stronie ECS i ALB przed przełączeniem na tryb produkcyjny

1. **ALB Target Group (`ticketdesk-tg`):** zmienić ścieżkę kontroli stanu z `/docs` na `/health` oraz włączyć atrybut ALB `routing.http.drop_invalid_header_fields.enabled = true`.
2. **Definicja zadania ECS (`ticketdesk-task`):** ustawić zmienne środowiskowe:
   - `APP_ENV=production`
   - `ALLOWED_HOSTS=ticketdesk.dev,www.ticketdesk.dev`
   - `TRUST_PROXY_HEADERS=true`
   - `COOKIE_SECURE=true`
   - `DB_SSLMODE=require`
   - `SECRET_KEY` (min. 32 znaki, najlepiej z AWS Secrets Manager)
3. **Route 53:** przepiąć rekord Alias `ticketdesk.dev` z `ticketdesk-alb` na dystrybucję CloudFront.
