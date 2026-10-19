# Kavach engine: one static binary. Build: docker build -t kavach .
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN cd engine && CGO_ENABLED=0 go build -o /kavach .

FROM alpine:3
COPY --from=build /kavach /usr/local/bin/kavach
ENTRYPOINT ["kavach"]
