#!/usr/bin/env nix-shell
#!nix-shell -i bash -p diffutils libxml2 libxslt perl poetry

# This script is used to update ./poetry-conversion.patch. Applying the patch
# will to convert this folder into a Poetry project.

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SETUP_PY=$(realpath "$THIS_DIR/../../setup.py")
REQUIREMENTS_TXT=$(realpath "$THIS_DIR/../../requirements.txt")
OUR_PYPROJECT_TOML="$THIS_DIR/pyproject.toml"
OUR_POETRY_LOCK="$THIS_DIR/poetry.lock"
GENERATED_POETRY_FILES=("$OUR_PYPROJECT_TOML" "$OUR_POETRY_LOCK")
PATCH_FILE="$THIS_DIR/poetry-conversion.patch"

# Prevent "ValueError: ZIP does not support timestamps before 1980"
# See nixpkgs manual.
unset SOURCE_DATE_EPOCH

set -e

# Sanity checks.
for f in $SETUP_PY $REQUIREMENTS_TXT ; do
  test -f "$f" || { echo "File $SETUP_PY doesn't exist! Aborting ..." ; exit 1; }
done
for f in "${GENERATED_POETRY_FILES[@]}" ; do
  test -f "$f" && { echo "File $f exists! Aborting ..." ; exit 1; }
done

# Extract some value from a variable/keyword argument in ./setup.py (removing
# (hopefully) all surrounding characters).
getFromSetupPy () {
  VARIABLE_NAME=$1
  grep -E "$VARIABLE_NAME\s?=" "$SETUP_PY" | sed -e 's/^.*= *//' -e 's/,.*$//' -e 's/"//g' -e "s/'//g"
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

# Make sure we run from here.
cd "$THIS_DIR"

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
perl -pe 's/([<=>]+)/:$1/' "$REQUIREMENTS_TXT" | tr '\n' ' ' | xargs -t -I {} bash -c "poetry add {}"

# Generate the patch file.
rm "$PATCH_FILE"
for f in "${GENERATED_POETRY_FILES[@]}" ; do
  diff -u /dev/null "$f" >> "$PATCH_FILE" || true # we expect differences
done

# Remove poetry files again.
rm "${GENERATED_POETRY_FILES[@]}"
