GO ?= go
DIST ?= dist
BINARY ?= cass-agent

.PHONY: help install uninstall test verify check-entrypoints test-rt-live run fmt build-linux-amd64 build-linux-arm64 build-linux-all docker-build docker-up fitness eval-models eval-zabbix eval-pegasus eval-headtohead eval-ablate eval-prompt-ab eval-lead eval-rt-shape probe netbox-probe

# Default target: say what exists. A bare `make` that silently builds one
# thing tells a newcomer nothing about the other fifteen.
help:
	@echo 'Setup and checks:'
	@echo '  make test              unit tests; no credentials, no network'
	@echo '  make install           put `ask` on your PATH (PREFIX=... to choose where)'
	@echo '  make verify            everything that must pass before main; no credentials'
	@echo '  make check-entrypoints check install, uninstall, and ask startup'
	@echo '  make test-rt-live      RT invariants against live data (needs RT credentials)'
	@echo '  make eval-rt-shape     does the model bound a ticket-age question (needs credentials)'
	@echo '  make fmt               gofmt the tree'
	@echo ''
	@echo 'These need:  source ~/.config/sroiaaa/env'
	@echo '  make probe             ask the Zabbix trap questions and judge them by eye'
	@echo '  make netbox-probe      reconnaissance against the NetBox API (no connector yet)'
	@echo '  make eval-zabbix       grade the Zabbix path end to end'
	@echo '  make eval-pegasus      grade model-authored SQL'
	@echo '  make eval-headtohead MODELS="a b"  compare two models over six question shapes'
	@echo '  make eval-prompt-ab    compare two prompts on the same binary'
	@echo '  make eval-lead         measure the lead-with-the-failure rule alone'
	@echo '  make eval-ablate       which prompt rules this model needs'
	@echo '  make eval-models       intent routing across several models'
	@echo ''
	@echo 'Reports are written to runtime/*.md and printed to stdout.'

# Puts `ask` on your PATH, at a location the person installing chooses:
#
#   make install                     ~/.local/bin, or ~/bin if that is what you have
#   make install PREFIX=/opt/cass ~/somewhere else
#
# A symlink rather than a copy, so it cannot go stale the way a hand-placed
# binary in ~/bin did -- that one was two days and four connector changes
# behind the source when it was noticed, and said nothing about it.
#
# Deliberately NOT done by putting bin/ on your PATH. A repository on PATH
# means any commit, from anyone, becomes an executable you run by typing a
# common word, which is a poor arrangement for a project about bounded access.
PREFIX ?= $(if $(wildcard $(HOME)/bin),$(HOME)/bin,$(HOME)/.local/bin)

install:
	@mkdir -p $(PREFIX)
	@ln -sf $(CURDIR)/bin/ask $(PREFIX)/ask
	@echo 'linked $(PREFIX)/ask -> $(CURDIR)/bin/ask'
	@case ":$$PATH:" in *":$(PREFIX):"*) ;; \
	  *) echo 'NOTE: $(PREFIX) is not on your PATH; add it in ~/.bashrc' ;; esac
	@echo 'try:  ask "how many agents are disconnected right now?"'

uninstall:
	@rm -f $(PREFIX)/ask
	@echo 'removed $(PREFIX)/ask'

test:
	$(GO) test ./...

# The gate for main. Formatting, build, vet, the full test suite, the entry
# points, that the build-tagged live tests still compile and still do not run
# by accident, and that the RT grader agrees with itself. No credentials, no
# network, every check reported rather than the first one aborting the rest.
#
# There is no CI. This is the gate only while somebody runs it.
verify:
	@sh ./scripts/verify.sh

# The path a new contributor walks before any Go test is relevant: make
# install, then typing `ask`. Needs no credentials and no network.
check-entrypoints:
	@sh ./scripts/check_entrypoints.sh

# Request Tracker invariants against the live instance: that a bound reaches
# RT, that it filters the side it claims, that a census covers every matching
# ticket or says why not, that the queue allowlist holds, that no ticket body
# leaves the connector, and that the total matches RT answering the same
# question directly.
#
# Behind a build tag rather than an environment check, so it cannot join
# `make test` even on a machine that has credentials sourced. That run stays
# credential-free and offline; a suite that fails when a service is down
# teaches people to ignore it.
#
# No model is involved. These verify the machinery. Whether an ANSWER improved
# is a question about the model, and needs repetition rather than assertion.
test-rt-live:
	$(GO) test -tags rtlive -count=1 -v ./internal/connector/ -run TestRTLive

# Whether the model proposes the right SHAPE for a ticket-age question, read
# from the trace rather than graded out of prose. Five phrasings that must
# acquire a bound and three controls that must not: a prompt teaching "reach
# for until" can overshoot into bounding questions that take no bound, and a
# suite without controls could only ever report success.
#
# Runs its own grader self-test first and refuses to measure a model with a
# grader it has not checked.
eval-rt-shape:
	python3 ./scripts/eval_rt_shape.py

run:
	$(GO) run ./cmd/cass-agent

fmt:
	$(GO) fmt ./...

build-linux-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/cass-agent

build-linux-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/cass-agent

build-linux-all: build-linux-amd64 build-linux-arm64

docker-build:
	docker build -t cass:phase1 .

docker-up:
	docker compose up --build

fitness:
	sh ./scripts/harness_fitness.sh

# Evaluations need live credentials exported into the environment, which the
# runtime env file provides:  source ~/.config/sroiaaa/env
#
# Each one prints to stdout AND writes runtime/<name>.md. If you go looking for
# the results afterwards, that is where they are -- with a .md suffix, which is
# why `find . -name eval-zabbix` finds nothing.
eval-models:
	python3 ./scripts/eval_models.py

eval-zabbix:
	python3 ./scripts/eval_zabbix.py

eval-pegasus:
	python3 ./scripts/eval_pegasus.py

# A comparison needs two models named; there is no default pair, because the
# one that used to be here named models the gateway stopped serving.
eval-headtohead:
	python3 ./scripts/eval_headtohead.py $(MODELS)

eval-ablate:
	python3 ./scripts/eval_ablate.py

eval-prompt-ab:
	python3 ./scripts/eval_prompt_ab.py

eval-lead:
	python3 ./scripts/eval_lead.py

# Not an evaluation: it prints answers and what a right and a wrong one look
# like, for a person to judge.
probe:
	sh ./bin/zabbix-probe.sh

# NetBox has no connector yet, so this talks to the API directly rather than
# asking Cass anything. Learning what a source actually returns is the step
# that comes before teaching the broker to ask it; every trap in the Zabbix
# guide was found this way and none were in the vendor documentation.
netbox-probe:
	sh ./bin/netbox-probe.sh
