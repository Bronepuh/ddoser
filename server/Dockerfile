FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn --frozen-lockfile
COPY . .
RUN yarn build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
# установить только прод-зависимости
COPY --from=builder /app/package.json /app/yarn.lock ./
RUN yarn --production --frozen-lockfile
# приложить собранный dist
COPY --from=builder /app/dist ./dist
EXPOSE 3000
CMD ["node","dist/main.js"]