FROM node:20-alpine

ENV NODE_ENV=production PORT=3000

WORKDIR /app

RUN addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -h /app -s /sbin/nologin -G app app \
    && mkdir -p /app-data \
    && chown app:app /app-data \
    && chmod 0750 /app-data

COPY package.json ./
COPY server.js index.html ./
COPY lib ./lib

RUN chmod 0555 /app /app/lib \
    && chmod 0444 /app/package.json /app/server.js /app/index.html /app/lib/*.js

USER app

ENV DATA_DIR=/app-data
ENV UPLOAD_DIR=/app-data/uploads

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||'3000')+'/health/live').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
