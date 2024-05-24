#!/bin/bash

echo "Running p1 tests..."

./pkgchecker resources/pkgs/incomplete_1.bpkg -min_hashes > file1.out
#./pkgchecker resources/pkgs/incomplete_4.bpkg -min_hashes > file4.out

diff -q file1.out ./tests/p1test/file1.expected
#diff -q file4.out ./tests/p1test/file4.expected


