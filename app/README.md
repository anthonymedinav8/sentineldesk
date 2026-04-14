# SentinelDesk

SentinelDesk is a security API that monitors authentication logs and detects brute force attacks, credential stuffing, and suspicious login times.
## Tech Stach
-Python 3.14
-Flask
-PostgredSQL
-psycopg2

## Features
- **Brute Force Detection** - flags IPs with 5+ failed logins within 10 minutes
- **Credential Stuffing Detection** - flags IPs attempting 5+ different usernames within 10 minutes
- **Suspicious Login Times** - flags logins occurring before 6AM or after 10PM

## Endpoints
- 'POST /logs' - ingest an authentication log entry
- GET 7allerts' - returs all active security alerts

## SETUP
1. Clone the repo
2. Create a '.env' file with 'DB_PASSWORD'
3. Create a PostdreSQL database named'sentineldesk'
4. Run 'pip install -r requirements.txt'
5. Run 'python app/main.py'