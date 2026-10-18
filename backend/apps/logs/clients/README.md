# Sending application logs to Densight

Connect the application in Densight (**Server logs → Connect a server → Python app / Node.js app**) to get
its ingest key and these instructions with the key filled in.

- `densight_logging.py`: a `logging.Handler` for any Python app (Django, Flask, FastAPI, scripts).
  Standard library only.
- `densight-logger.js`: a batching sender for Node.js 18+, with a stream for pino and a transport for
  winston. No dependencies.

Anything else can post JSON to `POST /api/ingest/` with `Authorization: Bearer dsl_...`: an array of
records, one record, or one per line. Useful fields: `timestamp`, `level`, `message`, `logger`, `service`,
`exception` (`type`, `value`, `stacktrace`) or `err` (`type`, `message`, `stack`), and for web requests
`method`, `path`, `status`, `ip`, `user`.

Passwords, API keys, tokens and card numbers are masked by Densight before anything is stored, but they
should not be logged in the first place: Densight flags it when they are.
