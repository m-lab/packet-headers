# Build packet-headers
FROM golang:1.12 as build
RUN apt-get update && apt-get install -y libpcap-dev
COPY . /go/src/github.com/m-lab/packet-headers
WORKDIR /go/src/github.com/m-lab/packet-headers
RUN go get -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" \
      .
RUN chmod a+rx /go/bin/packet-headers

# Put it in its own image.
FROM alpine
COPY --from=build /go/bin/packet-headers /
WORKDIR /
ENTRYPOINT ["/packet-headers"]
