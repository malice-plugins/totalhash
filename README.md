## #totalhash

# malice-totalhash

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/totalhash.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/totalhash.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/totalhash/latest.svg)](https://imagelayers.io/?images=malice/totalhash:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/totalhash/latest.svg)](https://imagelayers.io/?images=malice/totalhash:latest)

Malice #totalhash Plugin

This repository contains a **Dockerfile** of **malice/totalhash** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/totalhash/) published to the public [DockerHub](https://index.docker.io/).

### Dependencies

* [gliderlabs/alpine:3.3](https://index.docker.io/_/gliderlabs/alpine/)


### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/totalhash/) from public [DockerHub](https://hub.docker.com): `docker pull malice/totalhash`

### Usage

    docker run --rm malice/totalhash MD5/SHA1

```bash
Usage: totalhash [OPTIONS] COMMAND [arg...]

Malice `#totalhash` Plugin

Version: v0.1.0, BuildTime: 20160219

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t	output as Markdown table
  --help, -h	show help
  --version, -v	print the version

Commands:
  help	Shows a list of commands or help for one command

Run 'totalhash COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output **sandbox** JSON:
```json
{
  "totalhash": {
  }
}
```
### Sample Output **whitelist** (Markdown Table):
---
#### #totalhash
| Found | Filename    | Description | ProductName                        |
| ----- | ----------- | ----------- | ---------------------------------- |
| true  | notepad.exe | Notepad     | Microsoft Windows Operating System |
---

### To Run on OSX
 - Install [Homebrew](http://brew.sh)

```bash
$ brew install caskroom/cask/brew-cask
$ brew cask install virtualbox
$ brew install docker
$ brew install docker-machine
$ docker-machine create --driver virtualbox malice
$ eval $(docker-machine env malice)
```

### Documentation

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-av/issues/new) and I'll get right on it.

### Credits

### License
MIT Copyright (c) 2016 **blacktop**

[hub]: https://hub.docker.com/r/malice/totalhash/
