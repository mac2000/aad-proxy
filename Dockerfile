FROM golang:1.17-alpine as build

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /aad-proxy

FROM alpine

WORKDIR /

COPY --from=build /aad-proxy /aad-proxy

EXPOSE 8080

ENTRYPOINT ["/aad-proxy"]
