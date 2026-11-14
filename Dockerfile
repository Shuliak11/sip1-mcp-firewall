FROM node:22-alpine
LABEL org.opencontainers.image.title="SHULIAK SIP-1 Zero-Egress MCP Firewall"
LABEL org.opencontainers.image.source="https://github.com/Shuliak11/sip1-mcp-firewall"
LABEL org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
ENV NODE_ENV=production
COPY package.json server.json glama.json LICENSE README.md ./
COPY bin ./bin
COPY src ./src
COPY dist ./dist
COPY tests ./tests
RUN chmod +x /app/bin/sip1-mcp.js
USER node
ENTRYPOINT ["node", "/app/bin/sip1-mcp.js"]
