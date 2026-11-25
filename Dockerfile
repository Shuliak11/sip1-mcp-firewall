FROM node:22-alpine
LABEL org.opencontainers.image.title="SHULIAK SIP v3.1.0 Zero-Egress MCP Firewall & ISEP Blackbox" \
      org.opencontainers.image.version="3.1.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Shuliak11/sip1-mcp-firewall" \
      org.opencontainers.image.url="https://shuliak.dev"
WORKDIR /app
ENV NODE_ENV=production
COPY package.json action.yml ./
COPY src ./src
RUN chmod 0755 /app/src/cli.mjs && chown -R node:node /app
USER node
ENTRYPOINT ["node", "/app/src/cli.mjs"]
