#!/bin/bash

BFILE="complete_1"
BTEST="all_hashes"
BARGS="$BFILE.$BARGS.args"
BOUT="$BFILE.$BARGS.out"
BOUTSORTED="$BFILE.$BARGS_sorted.out"
cat $BARGS | xargs ./pkgchecker | sort | diff - $BOUTSORTED