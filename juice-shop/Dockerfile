# Stage 1: Build the logging proxy dependencies
FROM node:18-alpine AS proxy-builder
WORKDIR /logging-proxy
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Stage 2: Final image — Juice Shop + logging proxy
FROM bkimminich/juice-shop:latest

# We cannot use apk or supervisor because the latest Juice Shop image is distroless.
# We will use logging-proxy.js to natively spawn Juice Shop.

# Setup proxy directory and copy files with the default distroless user (10001 or 1001)
# The default user for bkimminich/juice-shop distroless is 65532 (nonroot)
COPY --chown=65532:65532 --from=proxy-builder /logging-proxy/node_modules /juice-shop/proxy/node_modules
COPY --chown=65532:65532 logging-proxy.js /juice-shop/proxy/logging-proxy.js

# We don't need package.json anymore since node_modules are built.
# Public-facing port (proxy). Juice Shop stays on internal :3000
EXPOSE 8080

USER 65532

CMD ["/juice-shop/proxy/logging-proxy.js"]
