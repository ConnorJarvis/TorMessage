# TorMessage
[![Build Status](https://travis-ci.com/ConnorJarvis/TorMessage.svg?branch=master)](https://travis-ci.org/ConnorJarvis/TorMessage)
[![Go Report Card](https://goreportcard.com/badge/github.com/ConnorJarvis/TorMessage)](https://goreportcard.com/report/github.com/ConnorJarvis/TorMessage)
[![Coverage Status](https://coveralls.io/repos/github/ConnorJarvis/TorMessage/badge.svg?branch=master&service=github)](https://coveralls.io/github/ConnorJarvis/TorMessage?branch=master)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FConnorJarvis%2FTorMessage.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FConnorJarvis%2FTorMessage?ref=badge_shield)

Work in progress messenger that communicates over Tor and supports forward secrecy

To build run:
- `go get go get golang.org/x/crypto/curve25519`
- `github.com/firstrow/tcp_server`
- `go build ./`

To start a conversation run:
- `./TorMessage -hostname 127.0.0.1:9000 -name Connor -host`

This will start hosting a conversation and output a base64 string
![Conversation Start](https://i.vangel.io/IOzbh.png)

To start the partner conversation run:
- `./TorMessage -hostname 127.0.0.1:9001 -name Connor2 -extradata $base64_string`

This base64 string contains the hostname, public key and 3 initial keys needed to initialize a conversation

To chat just enter text into the console

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FConnorJarvis%2FTorMessage.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FConnorJarvis%2FTorMessage?ref=badge_large)