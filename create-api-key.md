HOST=0.0.0.0
PORT=8743
DATABASE_URL=postgres://mindlock:mindlock@localhost/mindlock
API_SECRET=your-secret-key-here
RUST_LOG=mindlockd=info
RATE_LIMIT_RPM=60

by running this command to get api_secret:
openssl rand -hex 32
