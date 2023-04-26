# KO_DOCKER_REPO := gcr.io/my-project
KO_DOCKER_REPO := blairdrummond/rekor-sidekick

rekor-sidekick: FORCE
	go build .

FORCE: ;

build:
	ko build -L .

push:
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko build --platform all --bare .
