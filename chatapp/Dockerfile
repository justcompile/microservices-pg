FROM node:0.12

RUN mkdir /src

RUN npm install pm2 -g

WORKDIR /src
ADD app/package.json /src/package.json
RUN npm install

EXPOSE 3000

CMD npm start
