# Context: attack surface of https://dvwa-production-a515.up.railway.app

Collected by `enumerate_endpoints` before anything was tested.

| # | Method | URL | Parameter | Value | Siblings replayed |
|---|---|---|---|---|---|
| 1 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `username` | `(empty)` | `password`, `Login` |
| 2 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `password` | `(empty)` | `username`, `Login` |
| 3 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `Login` | `Login` | `username`, `password` |
| 4 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `ip` | `(empty)` | `Submit` |
| 5 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `Submit` | `Submit` | `ip` |
| 6 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/ | `password_new` | `(empty)` | `password_conf`, `Change` |
| 7 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/ | `password_conf` | `(empty)` | `password_new`, `Change` |
| 8 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/upload/ | `MAX_FILE_SIZE` | `100000` | `uploaded`, `Upload` |
| 9 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/upload/ | `uploaded` | `(empty)` | `MAX_FILE_SIZE`, `Upload` |
| 10 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `step` | `1` | `password_new`, `password_conf`, `Change` |
| 11 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `password_new` | `(empty)` | `step`, `password_conf`, `Change` |
| 12 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `password_conf` | `(empty)` | `step`, `password_new`, `Change` |
| 13 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `id` | `(empty)` | `Submit` |
| 14 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `Submit` | `Submit` | `id` |
| 15 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `id` | `(empty)` | `Submit` |
| 16 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `Submit` | `Submit` | `id` |
| 17 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_d/ | `default` | `English` | - |
| 18 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_r/ | `name` | `(empty)` | - |
| 19 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/csp/ | `include` | `(empty)` | - |
| 20 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/ | `token` | `8b479aefbd90795395b3e7089ae0dc09` | `phrase`, `send` |
| 21 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/ | `phrase` | `ChangeMe` | `token`, `send` |
| 22 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `message` | `(empty)` | `direction` |
| 23 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `direction` | `encode` | `message` |
| 24 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `password` | `(empty)` | - |
| 25 | POST | https://dvwa-production-a515.up.railway.app/security.php | `security` | `low` | `seclev_submit`, `user_token` |
| 26 | POST | https://dvwa-production-a515.up.railway.app/security.php | `user_token` | `d045ab50a1e0430cab5652ca7b2a5eff` | `security`, `seclev_submit` |

26 injection points across 13 endpoints.
