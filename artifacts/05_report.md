# SQL injection assessment - https://dvwa-production-a515.up.railway.app

27 injection points enumerated, 4 tested, **3 confirmed**.
Wall time 61.1s.

## Summary

The application contains three confirmed SQL injection vulnerabilities across different endpoints. Two are error-based injection points in numeric contexts, and one is a boolean-blind injection in a numeric context. The vulnerabilities allow attackers to extract or manipulate database content.

## Confirmed findings

### GET `id` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/
- Severity: critical
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /var/www/html/vulnerabilit...
- Fix: Use parameterized queries (prepared statements) with bound parameters instead of string concatenation. In PHP with MySQLi, use mysqli_prepare() and mysqli_stmt_bind_param(), or use PDO with prepared statements.

### GET `id` (boolean-blind)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/
- Severity: high
- Payload: `' AND '1'='1  vs  ' AND '1'='2`
- Requests used: 15
- Evidence: asymmetry confirmed - baseline 4703 bytes / TRUE 4703 / FALSE 4709, compared by content (TRUE matches baseline, FALSE differs)
- Fix: Use parameterized queries (prepared statements) with bound parameters instead of string concatenation. In PHP with MySQLi, use mysqli_prepare() and mysqli_stmt_bind_param(), or use PDO with prepared statements.

### GET `username` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- Severity: critical
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'd41d8cd98f00b204e9800998ecf8427e'' at line 1...
- Fix: Use parameterized queries (prepared statements) with bound parameters instead of string concatenation. In PHP with MySQLi, use mysqli_prepare() and mysqli_stmt_bind_param(), or use PDO with prepared statements.

---

Stage 2 and stage 4 were written by us.anthropic.claude-haiku-4-5-20251001-v1:0 via Bedrock. Every `confirmed` flag above came from core/verdict.py, which no model can reach.
