FROM node:22-alpine
WORKDIR /app
COPY agent/package.json agent/package-lock.json ./agent/
RUN cd agent && npm ci --omit=dev --no-audit --no-fund
COPY agent/ ./agent/
COPY circuits/ ./circuits/
RUN base64 -d circuits/gatekeeper.wasm.b64 > circuits/gatekeeper.wasm \
 && base64 -d circuits/gatekeeper_final.zkey.b64 > circuits/gatekeeper_final.zkey \
 && rm circuits/gatekeeper.wasm.b64 circuits/gatekeeper_final.zkey.b64
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
CMD ["node", "agent/server.js"]
