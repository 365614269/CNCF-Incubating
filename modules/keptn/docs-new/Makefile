ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# renovate: datasource=docker depName=squidfunk/mkdocs-material
MKDOCS_DOCKER_IMAGE_VERSION=9.5.3
MKDOCS_DOCKER_IMAGE=squidfunk/mkdocs-material

INTERACTIVE:=$(shell [ -t 0 ] && echo 1)
PORT := 8000

DOCKER_CMD := docker run --rm $(INTERACTIVE_FLAG)

ifdef INTERACTIVE
# is a terminal
INTERACTIVE_FLAG := -it
else
INTERACTIVE_FLAG := -t
endif

PWD=$(shell pwd)

.PHONY: docs-build
docs-build:
	$(DOCKER_CMD) -v ${PWD}/docs-new:/docs-new \
		-v ${PWD}/mkdocs.yml:/mkdocs.yml \
		-v ${PWD}/requirements.txt:/requirements.txt \
		-v ${PWD}/site:/site \
		-v ${PWD}/.git:/.git \
		-v ${PWD}/tmp/.pip-cache:/root/.cache/pip \
		--entrypoint "" \
		${MKDOCS_DOCKER_IMAGE}:${MKDOCS_DOCKER_IMAGE_VERSION} \
		sh -c 'cd /; pip install -r requirements.txt -q; mkdocs build'

.PHONY: docs-serve
docs-serve:
	$(DOCKER_CMD) -p $(PORT):$(PORT) \
		-v ${PWD}/docs-new:/docs-new \
		-v ${PWD}/mkdocs.yml:/mkdocs.yml \
		-v ${PWD}/requirements.txt:/requirements.txt \
		-v ${PWD}/site:/site \
		-v ${PWD}/.git:/.git \
		-v ${PWD}/tmp/.pip-cache:/root/.cache/pip \
		--entrypoint "" \
		${MKDOCS_DOCKER_IMAGE}:${MKDOCS_DOCKER_IMAGE_VERSION} \
		sh -c 'cd /; pip install -r requirements.txt -q; mkdocs serve --dirty -a 0.0.0.0:$(PORT)'

.PHONY: htmltest

# renovate: datasource=docker depName=wjdp/htmltest
HTMLTEST_VERSION := v0.17.0
htmltest: docs-build
	$(DOCKER_CMD) \
		-v $(PWD)/docs-new/.htmltest.yml:/.htmltest.yml \
		-v ${PWD}/site:/site \
		-v ${PWD}/tmp/.htmltest:/tmp/.htmltest \
		wjdp/htmltest:$(HTMLTEST_VERSION) -c /.htmltest.yml /site

.PHONY: lint lint-fix
lint: markdownlint
lint: lint-fix

# Markdown lint configuration
#
# - .markdownlintignore holds the configuration for files to be ignored
# - .markdownlint.yaml contains the rules for markdownfiles
# renovate: datasource=docker depName=davidanson/markdownlint-cli2-rules
MDL_DOCKER_VERSION := v0.11.0
MDL_CMD := docker run -v $(ROOT_DIR)../:/workdir --rm 

.PHONY: markdownlint markdownlint-fix
markdownlint:
	$(MDL_CMD) davidanson/markdownlint-cli2-rules:${MDL_DOCKER_VERSION} "**/*.md" 

markdownlint-fix:
	$(MDL_CMD) --entrypoint="markdownlint-cli2-fix" davidanson/markdownlint-cli2-rules:${MDL_DOCKER_VERSION} "**/*.md" 
