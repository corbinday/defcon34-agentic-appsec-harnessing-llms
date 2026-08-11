# Context: attack surface of https://dvwa-production-a515.up.railway.app

Collected by `enumerate_endpoints` before anything was tested.

| # | Method | URL | Parameter | Value | Siblings replayed |
|---|---|---|---|---|---|
| 1 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `id` | `(empty)` | `Submit` |
| 2 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `Submit` | `Submit` | `id` |
| 3 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `id` | `(empty)` | `Submit` |
| 4 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `Submit` | `Submit` | `id` |
| 5 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `username` | `(empty)` | `password`, `Login` |
| 6 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `password` | `(empty)` | `username`, `Login` |
| 7 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `Login` | `Login` | `username`, `password` |
| 8 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `ip` | `(empty)` | `Submit` |
| 9 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `Submit` | `Submit` | `ip` |
| 10 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_r/ | `name` | `(empty)` | - |
| 11 | POST | https://dvwa-production-a515.up.railway.app/security.php | `security` | `(empty)` | `seclev_submit`, `user_token` |
| 12 | POST | https://dvwa-production-a515.up.railway.app/security.php | `user_token` | `beb72050542f9d431f92fefa55c96901` | `security`, `seclev_submit` |

12 injection points across 6 endpoints.
