# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = "VulnerableCode"
copyright = "nexB Inc. and others"
author = "nexB Inc. and others"


# -- General configuration ---------------------------------------------------

# Ensure there are no invalid URLs
# Use -b linkcheck to check integrity of all external links
nitpicky = True
linkcheck_anchors = False  # See: https://github.com/sphinx-doc/sphinx/issues/9016
linkcheck_ignore = [
    r"http://localhost:\d+/",
    r"http://127.0.0.1:\d+/",
    "https://api.github.com/graphql",  # Requires auth
    "https://anongit.gentoo.org/git/data/glsa.git",  # Git only link
    "https://www.softwaretestinghelp.com/how-to-write-good-bug-report/",  # Cloudflare protection
    "https://www.openssl.org/news/vulnerabilities.xml",  # OpenSSL legacy advisory URL, not longer available
    "https://example.org/api/non-existent-packages",
    "https://github.com/aboutcode-org/vulnerablecode/pull/495/commits",
    "https://nvd.nist.gov/products/cpe",
    "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml",
    "http://ftp.suse.com/pub/projects/security/yaml/",
]

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = []

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = []
html_static_path = ["_static"]

html_css_files = [
    "theme_overrides.css",
]

master_doc = "index"
