malice-totalhash
================

[![Circle CI](https://circleci.com/gh/maliceio/malice-totalhash.png?style=shield)](https://circleci.com/gh/maliceio/malice-totalhash) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/totalhash.svg)](https://hub.docker.com/r/malice/totalhash/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/totalhash.svg)](https://hub.docker.com/r/malice/totalhash/) [![Docker Image](https://img.shields.io/badge/docker image-22.21 MB-blue.svg)](https://hub.docker.com/r/malice/totalhash/)

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
  --verbose, -V		verbose output
  --elasitcsearch value	elasitcsearch address for Malice to store results [$MALICE_ELASTICSEARCH]
  --post, -p		POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x		proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t		output as Markdown table
  --user value		totalhash user [$MALICE_TH_USER]
  --key value		totalhash key [$MALICE_TH_KEY]
  --help, -h		show help
  --version, -v		print the version

Commands:
  help	Shows a list of commands or help for one command

Run 'totalhash COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output **sandbox** JSON:

```json
{
  "totalhash": {
    "md5": "9483ba381cdb7c983e630839a0d2a1c3",
    "sha1": "4af607a4ecf7885018ab5a788e8f0607b4fcb08b",
    "time": "2015-08-02 00:49:35",
    "version": "0.3",
    "calltree": {
      "process_call": [
        {
          "filename": "C:\\malware.exe",
          "index": "1",
          "pid": "1348",
          "startreason": "AnalysisTarget"
        },
      ...
      ]
    },
    "static": {
      "strings_md5": "ac33aca979aaeee66a70b6a6ad9538bf",
      "strings_sha1": "b24c81ba5dc75edbbd6de5804e7b4a1db38db591",
      "av": [
        {
          "av_product": "bull",
          "scanner": "BullGuard",
          "signature": "Gen:Variant.Graftor.18194",
          "timestamp": "2015-08-01 15:55:42",
          "update": "2015-07-31 07:26:09",
          "version": "14.1.0.0"
        },
        ...
        {
          "av_product": "clam",
          "scanner": "ClamAV",
          "signature": "Trojan.Dropper-22795",
          "timestamp": "2015-08-01 15:55:42",
          "update": "2015-07-31 12:00:00",
          "version": "0.97.8.0"
        }
      ],
      "imphash": {
        "value": "3243b13e562279ab7fbe2f31e45d3a95"
      },
      "imports": [
        {
          "dll": "kernel32.dll"
        }
      ],
      "language": {
        "value": "040904B0"
      },
      "magic": {
        "value": "PE32 executable for MS Windows (GUI) Intel 80386 32-bit"
      },
      "packer": {
        "value": "UPX -> www.upx.sourceforge.net"
      },
      "pehash": {
        "value": "452dda12aae437d193c043388cfc8e1cf9dd0787"
      },
      "section": [
        {
          "md3": "d41d8cd98f00b204e9800998ecf8427e",
          "name": "UPX0",
          "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
          "size": "0"
        },
        {
          "md3": "be7cee8566021aa22591d9bf68634a88",
          "name": "UPX1",
          "sha1": "f9665ffa7f1b1f10e6265d7e1bf651a3c09793d2",
          "size": "47616"
        },
        {
          "md3": "6e964a0172c2edaff9838cbf467ab13e",
          "name": ".rsrc",
          "sha1": "e793ae7e3e91e59b1195cb8e283194d811013f88",
          "size": "130560"
        },
        {
          "md3": "bf619eac0cdf3f68d496ea9344137e8b",
          "name": ".Kerbero",
          "sha1": "5c3eb80066420002bc3dcc7ca4ab6efad7ed4ae5",
          "size": "512"
        },
        {
          "md3": "bf619eac0cdf3f68d496ea9344137e8b",
          "name": ".Kerbero",
          "sha1": "5c3eb80066420002bc3dcc7ca4ab6efad7ed4ae5",
          "size": "512"
        },
        {
          "md3": "86759dc484cc49f4800f7f13a4df40d1",
          "name": ".Kerbero",
          "sha1": "27d7d38a1cff80b297b1e4829cf6139af83a038e",
          "size": "66048"
        }
      ],
      "timestamp": {
        "value": "2009-09-12 18:01:17"
      },
      "version": {
        "value": "LegalCopyright:  \nInternalName: rootwarez.org\nFileVersion:  \nCompanyName:  \nLegalTrademarks:  \nComments:  \nProductName:  \nProductVersion: 2.01\nFileDescription:  \nOriginalFilename:   .exe\n"
      }
    }
  }
}

```

### Sample Output **whitelist** (Markdown Table):

---

#### #totalhash
| Found              | URL                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------- |
| :white_check_mark: | [link](https://totalhash.cymru.com/analysis/?4af607a4ecf7885018ab5a788e8f0607b4fcb08b) |

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
