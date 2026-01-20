from --platform=arm64   node:20-alpine3.20 as build     
WORKDIR /app
COPY package*.json ./   
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["node", "dist/main"]
