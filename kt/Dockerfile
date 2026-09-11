# The Z transparency log. State lives in KT_DATA (mount a volume); the
# signing seed is read from KT_SEED_FILE (mount it read-only).
FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
COPY lib ./lib
COPY tools ./tools
RUN adduser -D -H z-kt && mkdir -p /data && chown z-kt /data
USER z-kt
ENV KT_DATA=/data KT_HOST=0.0.0.0 KT_PORT=8085
EXPOSE 8085
CMD ["node", "server.js"]
