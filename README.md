# TorMessage
[![Build Status](https://travis-ci.com/ConnorJarvis/TorMessage.svg?branch=master)](https://travis-ci.org/ConnorJarvis/TorMessage)
[![Go Report Card](https://goreportcard.com/badge/github.com/ConnorJarvis/TorMessage)](https://goreportcard.com/report/github.com/ConnorJarvis/TorMessage)
[![Coverage Status](https://coveralls.io/repos/github/ConnorJarvis/TorMessage/badge.svg?branch=master&service=github)](https://coveralls.io/github/ConnorJarvis/TorMessage?branch=master)

Work in progress messenger that communicates over Tor and supports forward secrecy

To build run:
- `go get github.com/ConnorJarvis/TorMessage`
- `go build ./examples/command_line_chat.go`

To start a conversation run:
- `./command_line_chat -hostname 127.0.0.1:9000 -name Connor -host`

This will start hosting a conversation and output a base64 string
![Conversation Start](https://i.vangel.io/pMuVa.png)

To start the partner conversation run:
- `./command_line_chat -hostname 127.0.0.1:9001 -name Connor2 -extradata $base64_string`

This base64 string contains the hostname, public key and 3 initial keys needed to initialize a conversation

To chat just enter text into the console