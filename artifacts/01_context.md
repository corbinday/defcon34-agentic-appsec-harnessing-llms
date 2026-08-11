# Context: attack surface of https://dvwa-production-a515.up.railway.app

Collected by `enumerate_endpoints` before anything was tested.

| # | Method | URL | Parameter | Value | Siblings replayed |
|---|---|---|---|---|---|
| 1 | POST | https://dvwa-production-a515.up.railway.app/setup.php | `user_token` | `57d42d425153b6a2896225748384e50d` | `create_db` |
| 2 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `username` | `(empty)` | `password`, `Login` |
| 3 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `password` | `(empty)` | `username`, `Login` |
| 4 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ | `Login` | `Login` | `username`, `password` |
| 5 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `ip` | `(empty)` | `Submit` |
| 6 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/ | `Submit` | `Submit` | `ip` |
| 7 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/ | `password_new` | `(empty)` | `password_conf`, `Change` |
| 8 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/ | `password_conf` | `(empty)` | `password_new`, `Change` |
| 9 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/fi/ | `page` | `include.php` | - |
| 10 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/upload/ | `MAX_FILE_SIZE` | `100000` | `uploaded`, `Upload` |
| 11 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `step` | `1` | `password_new`, `password_conf`, `Change` |
| 12 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `password_new` | `(empty)` | `step`, `password_conf`, `Change` |
| 13 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/ | `password_conf` | `(empty)` | `step`, `password_new`, `Change` |
| 14 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `id` | `(empty)` | `Submit` |
| 15 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ | `Submit` | `Submit` | `id` |
| 16 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `id` | `(empty)` | `Submit` |
| 17 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ | `Submit` | `Submit` | `id` |
| 18 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_d/ | `default` | `English` | - |
| 19 | GET | https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_r/ | `name` | `(empty)` | - |
| 20 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/csp/ | `include` | `(empty)` | - |
| 21 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/ | `token` | `8b479aefbd90795395b3e7089ae0dc09` | `phrase`, `send` |
| 22 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/ | `phrase` | `ChangeMe` | `token`, `send` |
| 23 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `message` | `(empty)` | `direction` |
| 24 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `direction` | `encode` | `message` |
| 25 | POST | https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php | `password` | `(empty)` | - |
| 26 | POST | https://dvwa-production-a515.up.railway.app/security.php | `security` | `low` | `seclev_submit`, `user_token` |
| 27 | POST | https://dvwa-production-a515.up.railway.app/security.php | `user_token` | `a1815f34f0548ed5b0d2344e8905d176` | `security`, `seclev_submit` |
| 28 | GET | https://dvwa-production-a515.up.railway.app/instructions.php | `doc` | `readme` | - |

28 injection points across 16 endpoints.
