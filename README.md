malice-totalhash
================

[![Circle CI](https://circleci.com/gh/maliceio/malice-totalhash.png?style=shield)](https://circleci.com/gh/maliceio/malice-totalhash) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/totalhash.svg)](https://hub.docker.com/r/malice/totalhash/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/totalhash.svg)](https://hub.docker.com/r/malice/totalhash/) [![Docker Image](https://img.shields.io/badge/docker image-22.2 MB-blue.svg)](https://hub.docker.com/r/malice/totalhash/)

Malice #totalhash Plugin

This repository contains a **Dockerfile** of **malice/totalhash** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/totalhash/) published to the public [DockerHub](https://index.docker.io/).

### Dependencies

-	[malice/alpine](https://hub.docker.com/r/malice/alpine/)

### Installation

1.	Install [Docker](https://www.docker.io/).
2.	Download [trusted build](https://hub.docker.com/r/malice/totalhash/) from public [DockerHub](https://hub.docker.com): `docker pull malice/totalhash`

### Usage

```
docker run --rm malice/totalhash SHA1
```

```bash
Usage: totalhash [OPTIONS] COMMAND [arg...]

Malice totalhash Plugin

Version: v0.1.0, BuildTime: 20160219

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t	output as Markdown table
  --user 	totalhash user [$MALICE_TH_USER]
  --key 	totalhash key [$MALICE_TH_KEY]
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
|-------|-------------|-------------|------------------------------------|
| true  | notepad.exe | Notepad     | Microsoft Windows Operating System |

---

Documentation
-------------

### To write results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)

```bash
$ docker volume create --name malice
$ docker run -d --name elastic \
                -p 9200:9200 \
                -v malice:/usr/share/elasticsearch/data \
                 blacktop/elasticsearch
$ docker run --rm --link elastic malice/totalhash -t MD5/SHA1
```

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-totalhash/issues/new) and I'll get right on it.

### License

MIT Copyright (c) 2016 **blacktop**
