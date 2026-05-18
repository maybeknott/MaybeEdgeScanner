FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY assets ./assets
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/maybeedgescanner-sidecar .

FROM alpine:3.20
RUN adduser -D -H scanner
WORKDIR /app
COPY --from=build /out/maybeedgescanner-sidecar /app/maybeedgescanner-sidecar
COPY --from=build /src/assets /app/assets
USER scanner
EXPOSE 10808
ENTRYPOINT ["/app/maybeedgescanner-sidecar"]
