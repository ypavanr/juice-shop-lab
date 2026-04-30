# Stage 1: Build the logging proxy dependencies
FROM node:18-alpine AS proxy-builder
WORKDIR /logging-proxy
COPY package.json ./
RUN npm ci --omit=dev

# Stage 2: Final image — Juice Shop + logging proxy
FROM bkimminich/juice-shop:latest

USER root

# Install supervisord to run both processes
RUN apk add --no-cache supervisor

# Install logging proxy
COPY --from=proxy-builder /logging-proxy/node_modules /logging-proxy/node_modules
COPY logging-proxy.js /logging-proxy/logging-proxy.js
COPY package.json /logging-proxy/package.json

# Supervisord config
COPY supervisord.conf /etc/supervisord.conf

# Public-facing port (proxy). Juice Shop stays on internal :3000
EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
