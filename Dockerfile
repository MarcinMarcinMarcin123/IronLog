FROM node:20-alpine

# Wymagane do kompilacji better-sqlite3
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Folder na bazę danych
RUN mkdir -p /app/data

EXPOSE 3001

CMD ["node", "server.js"]
