FROM node:latest
RUN curl -fsSL https://deb.nodesource.com/setup | bash
RUN sudo npm install -g something
ADD ./src /app
USER app
CMD ["node", "/app/index.js"]
