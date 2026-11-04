# Build a minimal static Interlace image for CLI / CI scanning.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /interlace ./cmd/interlace

FROM gcr.io/distroless/static-debian12
COPY --from=build /interlace /interlace
# UI mode:   docker run -p 8080:8080 -p 8081:8081 interlace -open=false
# CLI scan:  docker run interlace scan https://target.example --fail-on high
EXPOSE 8080 8081 8082
ENTRYPOINT ["/interlace"]
