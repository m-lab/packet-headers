# packet-headers
[![Version](https://img.shields.io/github/tag/m-lab/packet-headers.svg)](https://github.com/m-lab/packet-headers/releases) [![Build Status](https://travis-ci.com/m-lab/packet-headers.svg?branch=master)](https://travis-ci.com/m-lab/packet-headers) [![Coverage Status](https://coveralls.io/repos/m-lab/packet-headers/badge.svg?branch=master)](https://coveralls.io/github/m-lab/packet-headers?branch=master) [![GoDoc](https://godoc.org/github.com/m-lab/packet-headers?status.svg)](https://godoc.org/github.com/m-lab/packet-headers) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/packet-headers)](https://goreportcard.com/report/github.com/m-lab/packet-headers)

The packet-headers service provides a binary which collects packet headers for
all incoming TCP flows and saves each stream of packet captures into a
per-stream `.pcap` file where the filename is the
[UUID](https://github.com/m-lab/uuid) of the TCP flow.  It only saves the
packet headers, and it supports (with a command-line flag) IP anonymity for
the saved addresses.


## Usage

```
$ ./packet-headers -help 2>&1 | fmt | sed -e 's/\t/        /g'

Usage of ./packet-headers:
  -anonymize.ip value
        Valid values are "none" and "netblock". (default none)
  -captureduration duration
        Only save the first captureduration of each flow, to prevent
        long-lived flows from spamming the hard drive. (default 30s)
  -datadir string
        The directory to which data is written (default ".")
  -flowtimeout duration
        Once there have been no packets for a flow for at least
        flowtimeout, the flow can be assumed to be closed. (default 30s)
  -interface value
        The interface on which to capture traffic. May be repeated. If
        unset, will capture on all available interfaces.
  -maxheadersize int
        The maximum size of packet headers allowed. A lower value allows
        the pcap process to be less wasteful but risks more esoteric
        IPv6 headers (which can theoretically be up to the full size
        of the packet but in practice seem to be under 128) getting
        truncated. (default 256)
  -maxidleram value
        How much idle RAM we should tolerate before we try and forcibly
        return it to the OS. (default 3GB)
  -prometheusx.listen-address string
         (default ":9990")
  -sigtermwait duration
        How long should the daemon hang around before exiting after
        receiving a SIGTERM. (default 1s)
  -stream
        Stream results to disk instead of buffering them in RAM.
  -tcpinfo.eventsocket string
        The filename of the unix-domain socket on which events are served.
  -uuidwaitduration duration
        Wait up to uuidwaitduration for each flow before either assigning
        a UUID or discarding all future packets. This prevents buffering
        unsaveable packets. (default 5s)

```

Running `packet-headers` also requires running
[`tcp-info`](https://github.com/m-lab/tcp-info) and setting it up with an
eventsocket.

## FAQ: What about UDP? ICMP?

A good idea, but not required for v1.
