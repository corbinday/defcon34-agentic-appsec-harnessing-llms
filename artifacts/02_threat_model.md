# Threat model - https://dvwa-production-a515.up.railway.app

## Entry points

- POST `user_token` on https://dvwa-production-a515.up.railway.app/setup.php
- GET `username` on https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- GET `password` on https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- GET `Login` on https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- POST `ip` on https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/
- POST `Submit` on https://dvwa-production-a515.up.railway.app/vulnerabilities/exec/
- GET `password_new` on https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/
- GET `password_conf` on https://dvwa-production-a515.up.railway.app/vulnerabilities/csrf/
- GET `page` on https://dvwa-production-a515.up.railway.app/vulnerabilities/fi/
- POST `MAX_FILE_SIZE` on https://dvwa-production-a515.up.railway.app/vulnerabilities/upload/
- POST `step` on https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/
- POST `password_new` on https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/
- POST `password_conf` on https://dvwa-production-a515.up.railway.app/vulnerabilities/captcha/
- GET `id` on https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/
- GET `Submit` on https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/
- GET `id` on https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/
- GET `Submit` on https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/
- GET `default` on https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_d/
- GET `name` on https://dvwa-production-a515.up.railway.app/vulnerabilities/xss_r/
- POST `include` on https://dvwa-production-a515.up.railway.app/vulnerabilities/csp/
- POST `token` on https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/
- POST `phrase` on https://dvwa-production-a515.up.railway.app/vulnerabilities/javascript/
- POST `message` on https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php
- POST `direction` on https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php
- POST `password` on https://dvwa-production-a515.up.railway.app/vulnerabilities/cryptography/index.php
- POST `security` on https://dvwa-production-a515.up.railway.app/security.php
- POST `user_token` on https://dvwa-production-a515.up.railway.app/security.php
- GET `doc` on https://dvwa-production-a515.up.railway.app/instructions.php

## Trust boundary

The browser sends parameters; PHP interpolates them into SQL and MariaDB executes the result. The boundary that matters sits between the request and the query string, and every confirmed finding below crossed it.

## What an attacker gains from a confirmed CWE-89 here

- Read any table the web user can reach, including the credentials table
- Bypass authentication where the injected parameter is part of a login test
- Depending on grants and secure_file_priv, write files and reach code execution

## Confirmed crossings

- https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/ `username` via error-based
- https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/ `id` via error-based
- https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/ `id` via boolean-blind
