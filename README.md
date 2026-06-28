# Incident Auth API

A small in-memory REST API for testing Copilot Studio agent calls with HTTP Basic authentication.

## Default auth

- Header key: `Authorization`
- Header value format: `Basic <base64(username:password)>`
- Required custom header key: ``
- Required custom header value: ``

The API now checks the Copilot header on all incident routes. Basic Auth helpers remain in the code for later use, but they are not used by the routes.

## Endpoints

- `GET /health` - no auth, simple health check
- `GET /auth-info` - shows the configured auth details
- `GET /incidents` - list all incidents, requires Basic Auth
- `GET /incidents/{incident_id}` - get one incident, requires Basic Auth
- `POST /incidents` - create incident, requires Basic Auth
- `PUT /incidents/{incident_id}` - update incident, requires Basic Auth
- `DELETE /incidents/{incident_id}` - delete incident, requires Basic Auth


