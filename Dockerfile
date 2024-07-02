FROM golang:1.20 as builder

WORKDIR /app

COPY ./pulsar/go.mod ./pulsar/go.sum ./
RUN go mod download

COPY ./pulsar/ .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./server

FROM alpine:latest

WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]