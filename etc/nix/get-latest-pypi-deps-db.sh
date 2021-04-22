#!/usr/bin/env bash

USER_SLASH_REPO="DavHau/pypi-deps-db"

DATA=$(curl "https://api.github.com/repos/$USER_SLASH_REPO/commits/master" | jq '.sha, .commit.author.date' | sed 's/"//g')
COMMIT=$(sed '1q;d' <<< "$DATA")
DATE=$(sed '2q;d' <<< "$DATA")
SHA256=$(nix-prefetch-url --unpack --type sha256 "https://github.com/$USER_SLASH_REPO/tarball/$COMMIT" | tail -n 1)

NIX_REV_ATTR="pypiDataRev = \"$COMMIT\"; # $DATE"
NIX_SHA_ATTR="pypiDataSha256 = \"$SHA256\";"

echo ""
echo $NIX_REV_ATTR
echo $NIX_SHA_ATTR

if [[ "$1" = "--in-place" ]] ; then
  # Replace the values in the flake.
  PATTERN="\s*\n?\s*\"[^\n]+" # <space><newline><space>"content...<newline>
  perl -i.bak1 -0777 -pe "s/pypiDataRev =$PATTERN/$NIX_REV_ATTR/" flake.nix
  perl -i.bak2 -0777 -pe "s/pypiDataSha256 =$PATTERN/$NIX_SHA_ATTR/" flake.nix
fi
