# build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn --frozen-lockfile
COPY . .
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL
RUN yarn build

# serve
FROM nginx:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
# базовый конфиг Nginx
RUN sed -i 's/listen       80;/listen 80;/' /etc/nginx/conf.d/default.conf
EXPOSE 3043
CMD ["nginx","-g","daemon off;"]
