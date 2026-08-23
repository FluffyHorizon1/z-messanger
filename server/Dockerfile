# Z relay — zero-knowledge, RAM-only. Runs fine with a read-only root fs.
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
USER node
# Render/Fly inject $PORT; locally we default to 8080.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8080}/health" || exit 1
CMD ["node", "server.js"]
