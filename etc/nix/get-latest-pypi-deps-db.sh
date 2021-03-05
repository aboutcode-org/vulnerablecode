#!/usr/bin/env bash

USER_SLASH_REPO="DavHau/pypi-deps-db"

DATA=$(curl "https://api.github.com/repos/$USER_SLASH_REPO/commits/master" | jq '.sha, .commit.author.date' | sed 's/"//g')
COMMIT=$(sed '1q;d' <<< "$DATA")
DATE=$(sed '2q;d' <<< "$DATA")
SHA256=$(nix-prefetch-url --unpack --type sha256 "https://github.com/$USER_SLASH_REPO/tarball/$COMMIT" | tail -n 1)

echo ""
echo "pypiDataRev = \"$COMMIT\"; # $DATE"
echo "pypiDataSha256 = \"$SHA256\";"
