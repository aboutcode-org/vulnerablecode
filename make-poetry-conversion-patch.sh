#!/usr/bin/env nix-shell
#!nix-shell -i bash -p diffutils libxml2 libxslt perl poetry

# This script is used to update ./poetry-conversion.patch. Applying the patch
# will to convert this folder into a Poetry project.

GENERATED_POETRY_FILES=(pyproject.toml poetry.lock)
PATCH_FILE=poetry-conversion.patch

# Sanity check.
for f in "${GENERATED_POETRY_FILES[@]}" ; do
  test -f "$f" && { echo "File $f exists! Aborting ..." ; exit 1; }
done

# Extract some value from a variable/keyword argument in ./setup.py (removing
# (hopefully) all surrounding characters).
getFromSetupPy () {
  VARIABLE_NAME=$1
  grep -E "$VARIABLE_NAME\s?=" setup.py | sed -e 's/^.*= *//' -e 's/,.*$//' -e 's/"//g' -e "s/'//g"
}

NAME=$(getFromSetupPy name)
VERSION=$(getFromSetupPy version)
DESC=$(getFromSetupPy desc)
AUTHOR=$(getFromSetupPy author)
AUTHOR_EMAIL=$(getFromSetupPy author_email)
AUTHORS="$AUTHOR <$AUTHOR_EMAIL>"
LICENSE=$(getFromSetupPy license)
PYTHON="^3.8"
DEFINE_MAIN_DEPS_INTERACTIVELY="no"
DEFINE_DEV_DEPS_INTERACTIVELY="no"
CONFIRM_GENERATION="yes"

# Create the pyproject.toml file using `poetry init` which runs interactively
# and asks a couple of questions. Answer them using predefined values.
poetry init <<EOF
$NAME
$VERSION
$DESC
$AUTHORS
$LICENSE
$PYTHON
$DEFINE_MAIN_DEPS_INTERACTIVELY
$DEFINE_DEV_DEPS_INTERACTIVELY
$CONFIRM_GENERATION
EOF

# Convert requirements.txt entries to pyproject.toml entries.
# https://github.com/python-poetry/poetry/issues/663
# This may take very long.
perl -pe 's/([<=>]+)/:$1/' requirements.txt | xargs -t -n 1 -I {} poetry add '{}'

# Generate the patch file.
rm $PATCH_FILE
for f in "${GENERATED_POETRY_FILES[@]}" ; do
  diff -u /dev/null "$f" >> $PATCH_FILE || true # we expect differences
done

# Remove poetry files again.
rm "${GENERATED_POETRY_FILES[@]}"
