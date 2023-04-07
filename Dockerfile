# Build packet-headers
FROM golang:1.19-alpine3.16 as build
RUN apk --no-cache add libpcap-dev git gcc libc-dev
COPY . /go/src/github.com/m-lab/packet-headers
WORKDIR /go/src/github.com/m-lab/packet-headers
RUN go install -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)$(git diff --quiet || echo dirty)" \
      .
RUN chmod a+rx /go/bin/packet-headers

# Put it in its own image.
FROM alpine:3.16
RUN apk --no-cache add libpcap libcap
COPY --from=build /go/bin/packet-headers /packet-headers
RUN setcap cap_net_raw=ep /packet-headers
WORKDIR /
ENTRYPOINT ["/packet-headers"]
