FROM golang:1.23-alpine

WORKDIR /app

COPY server.go .

ENV PORT=8080

EXPOSE 8080

CMD ["go", "run", "server.go"]
