import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { createServer } from 'node:tls';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function port(name) {
  const value = Number.parseInt(required(name), 10);
  if (!Number.isInteger(value) || value < 1 || value > 65_535) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

const listenPort = port('KONCLAVE_TLS_LISTEN_PORT');
const upstreamPort = port('KONCLAVE_TLS_UPSTREAM_PORT');
const server = createServer(
  {
    cert: readFileSync(required('KONCLAVE_TLS_CERT_FILE')),
    key: readFileSync(required('KONCLAVE_TLS_KEY_FILE')),
    minVersion: 'TLSv1.2',
  },
  (client) => {
    const upstream = connect({ host: '127.0.0.1', port: upstreamPort });
    const close = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('error', close);
    upstream.on('error', close);
    client.pipe(upstream);
    upstream.pipe(client);
  },
);

server.listen(listenPort, '127.0.0.1', () => {
  process.stdout.write('ready\n');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
