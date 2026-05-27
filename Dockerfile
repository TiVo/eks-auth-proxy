FROM node:20-slim

WORKDIR /app

RUN yarn global add pm2 -g

COPY package.json yarn.lock /app/

RUN yarn install --ignore-engines

COPY . /app

CMD ["./start"]
