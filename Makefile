REPO=malice
NAME=totalhash
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(REPO)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(REPO)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

test:
	docker run --rm $(REPO)/$(NAME):$(VERSION) --help

.PHONY: build size test
