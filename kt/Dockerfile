# The Z transparency log — and, with the command swapped, its witness.
# State lives in KT_DATA (mount a volume or a persistent disk); the signing
# seed comes from KT_SEED or KT_SEED_FILE (mount it read-only). The image
# starts as root only to hand the data directory and a mounted seed to the
# service user, then runs as z-kt (docker-entrypoint.sh).
#
#   docker run ... z-kt                        # the log (server.js)
#   docker run ... z-kt node tools/mirror.js   # a witness, configured by KT_* env
FROM node:22-alpine
RUN apk add --no-cache su-exec
WORKDIR /app
COPY package.json server.js docker-entrypoint.sh ./
COPY lib ./lib
COPY tools ./tools
RUN adduser -D -H z-kt && mkdir -p /data && chown z-kt /data && chmod 755 docker-entrypoint.sh
ENV KT_DATA=/data KT_HOST=0.0.0.0 KT_PORT=8085
EXPOSE 8085
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "server.js"]
