// Send a Node.js application's logs to Densight. No dependencies (Node 18+).
//
//   const { createDensight } = require('./densight-logger');
//   const densight = createDensight({ url: 'https://densight.example.com/api/ingest/', key: 'dsl_...', service: 'shop-api' });
//
// pino:     const logger = pino({}, pino.multistream([{ stream: process.stdout }, { stream: densight.stream }]));
// winston:  logger.add(new (densight.WinstonTransport())());   // with format.errors({ stack: true })
// anything: densight.send({ level: 'error', message: 'Payment failed', err });
//
// `release` (or the DENSIGHT_RELEASE environment variable) names the version
// or commit running, so Densight can tell which deploy introduced an error.
//
// Entries are batched and sent every 2 seconds; a Densight outage never
// throws inside the application.
'use strict';

const os = require('node:os');

function serializeError(err) {
  if (!(err instanceof Error)) return err;
  return { type: err.name, message: err.message, stack: err.stack };
}

function createDensight({
  url,
  key,
  service = '',
  environment = '',
  release = process.env.DENSIGHT_RELEASE || '',
  batchSize = 200,
  intervalMs = 2000,
}) {
  let buffer = [];
  const host = os.hostname();

  async function flush() {
    if (buffer.length === 0) return;
    const body = JSON.stringify(buffer.splice(0, buffer.length));
    try {
      await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body,
      });
    } catch {
      // dropped: logging must never crash the application
    }
  }

  const timer = setInterval(flush, intervalMs);
  timer.unref();
  process.once('beforeExit', flush);

  function send(entry) {
    const record = { service, environment, host, ...(release ? { release } : {}), ...entry };
    if (record.err) record.err = serializeError(record.err);
    if (record.error) record.error = serializeError(record.error);
    buffer.push(record);
    if (buffer.length >= batchSize) flush();
  }

  // pino writes one JSON line per entry to a stream.
  const stream = {
    write(line) {
      try {
        send(JSON.parse(line));
      } catch {
        send({ message: String(line) });
      }
    },
  };

  // A winston transport, created on demand so winston stays optional.
  function WinstonTransport() {
    const Transport = require('winston-transport');
    return class DensightTransport extends Transport {
      log(info, callback) {
        send({ ...info, timestamp: info.timestamp || new Date().toISOString() });
        callback();
      }
    };
  }

  return { send, flush, stream, WinstonTransport };
}

module.exports = { createDensight };
