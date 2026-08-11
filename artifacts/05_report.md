# SQL injection assessment - https://dvwa-production-a515.up.railway.app

27 injection points enumerated, 8 tested, **3 confirmed**.
Wall time 77.7s.

## Summary

The assessment identified three confirmed SQL injection vulnerabilities across DVWA's injection endpoints. Two are error-based (in the standard SQLi and brute-force modules), and one is boolean-blind (in the blind SQLi module). All three allow attackers to manipulate SQL queries through unsanitized user input.

## Confirmed findings

### GET `id` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli/
- Severity: critical
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /var/www/html/vulnerabilit...
- Fix: Use prepared statements with parameterized queries. Replace direct string concatenation with mysqli_prepare() and mysqli_bind_param(), or use an ORM. Example: $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $id); $stmt->execute();

### GET `id` (boolean-blind)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/sqli_blind/
- Severity: critical
- Payload: `' AND '1'='1  vs  ' AND '1'='2`
- Requests used: 15
- Evidence: asymmetry confirmed - baseline 4703 bytes / TRUE 4703 / FALSE 4709, compared by content (TRUE matches baseline, FALSE differs)
- Fix: Use prepared statements with parameterized queries. Replace direct string concatenation with mysqli_prepare() and mysqli_bind_param(), or use an ORM. Example: $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $id); $stmt->execute();

### GET `username` (error-based)

- URL: https://dvwa-production-a515.up.railway.app/vulnerabilities/brute/
- Severity: critical
- Payload: `'`
- Requests used: 3
- Evidence: DB error fingerprint 'You have an error in your SQL syntax' in response: ...or</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'd41d8cd98f00b204e9800998ecf8427e'' at line 1...
- Fix: Use prepared statements with parameterized queries. Replace direct string concatenation with mysqli_prepare() and mysqli_bind_param(), or use an ORM. Example: $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?"); $stmt->bind_param("s", $username); $stmt->execute();

---

Stage 2 and stage 4 were written by us.anthropic.claude-haiku-4-5-20251001-v1:0 via Bedrock. Every `confirmed` flag above came from core/verdict.py, which no model can reach.
