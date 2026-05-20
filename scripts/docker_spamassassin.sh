#!/usr/bin/env bash
# scripts/docker_spamassassin.sh — Phase 3: launch local SpamAssassin.
#
# Starts the instantlinux/spamassassin container on port 783 (the default
# spamd port that src/checks/spamassassin_check.py connects to via
# aiospamc / spamassassin_client).
#
# Intended contents (to be filled in Phase 3):
#   docker run -d --name spamd \
#       -p 783:783 \
#       instantlinux/spamassassin
#
# Volumes and custom rule configuration deferred past the PoC.
