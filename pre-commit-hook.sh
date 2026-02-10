#!/bin/sh
#
# Copyright 2026 Stakater.
#
# This file is meant to be used as a pre-commit hook for git.
# It checks if there are any staged .go files, and if so, it runs
# the 'make pre-commit' command to perform various checks and
# formatting on the code.
# If the checks fail, it prevents the commit from being made.
#
# To use this hook, symlink it to .git/hooks/pre-commit on your local repository:
# ln -s ../../pre-commit-hook.sh .git/hooks/pre-commit
#

STAGED_GO_FILES=$(git diff --cached --name-only | grep ".go$")

if [[ "$STAGED_GO_FILES" = "" ]]; then
  exit 0
fi

make pre-commit
RES=$?

if ! $RES; then
	printf "COMMIT FAILED!\n"
	exit 1
else
	printf "COMMIT SUCCEEDED!\n"
fi

exit 0

