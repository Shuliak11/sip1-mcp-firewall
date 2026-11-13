FROM node:22-alpine
WORKDIR /app
COPY package.json server.json glama.json LICENSE README.md ./
COPY bin ./bin
COPY src ./src
COPY dist ./dist
COPY tests ./tests
USER node
ENTRYPOINT ["node", "bin/sip1-mcp.js"]
