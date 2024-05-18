#!/bin/bash

set -e

include_path = include
src_path = src
resources_path = resources
pkgs_path = $resources_path/pkgs
getting_started_path = $resources_path/getting_started

pkgchecker = pkgchecker

echo "Running p1 tests..."

file1_bpkg = $pkgs_path/file1.bpkg
file4_bpkg = $pkgs_path/file4.bpkg

./pkgchecker > file1.out
./pkgchecker > file4.out

diff -q file1.out ./tests/p1test/file1.expected
diff -q file4.out ./tests/p1test/file4.expected
