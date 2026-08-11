# SQL injection assessment - https://dvwa-production-a515.up.railway.app

26 injection points enumerated, 6 tested, **3 confirmed**.
Wall time 45.9s.

## Confirmed findings

### GET `id` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /var/www/html/vulnerabilit...
- Severity: high
- Fix: Bind this parameter as a query placeholder. In PHP, `mysqli_prepare` with `bind_param`, never string concatenation.

### GET `id` (boolean-blind)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/
- Payload: `' AND '1'='1  vs  ' AND '1'='2`
- Requests used: 8
- Evidence: asymmetry confirmed - baseline 4703 bytes / TRUE 4703 / FALSE 4709, compared by content (TRUE matches baseline, FALSE differs)
- Severity: high
- Fix: Bind this parameter as a query placeholder. In PHP, `mysqli_prepare` with `bind_param`, never string concatenation.

### GET `username` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'd41d8cd98f00b204e9800998ecf8427e'' at line 1...
- Severity: high
- Fix: Bind this parameter as a query placeholder. In PHP, `mysqli_prepare` with `bind_param`, never string concatenation.
