# Incident Auth API

A small in-memory REST API for testing Copilot Studio agent calls with HTTP Basic authentication.

## Default auth

- Header key: `Authorization`
- Header value format: `Basic <base64(username:password)>`
- Default username: `agentuser`
- Default password: `agentpass`
- Base64 token for the default credentials: `YWdlbnR1c2VyOmFnZW50cGFzcw==`

Use this full header value in the agent:

`Authorization: Basic YWdlbnR1c2VyOmFnZW50cGFzcw==`

## Endpoints

- `GET /health` - no auth, simple health check
- `GET /auth-info` - shows the configured auth details
- `GET /incidents` - list all incidents, requires Basic Auth
- `GET /incidents/{incident_id}` - get one incident, requires Basic Auth
- `POST /incidents` - create incident, requires Basic Auth
- `PUT /incidents/{incident_id}` - update incident, requires Basic Auth
- `DELETE /incidents/{incident_id}` - delete incident, requires Basic Auth

## Sample render start command

```bash
uvicorn app:app --host 0.0.0.0 --port $PORT
```

## Local run

```bash
python -m pip install -r requirements.txt
python app.py
```

## Example request

```bash
curl -H "Authorization: Basic YWdlbnR1c2VyOmFnZW50cGFzcw==" http://localhost:10000/incidents
```