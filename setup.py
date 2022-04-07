#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup

requirements = [
    r.strip() for r in open("requirements.txt") if r.strip() and not r.strip().startswith("#")
]

desc = "Software package vulnerabilities database."

setup(
    name="vulnerablecode",
    version="30.0.0",
    license="Apache-2.0",
    description=desc,
    long_description=desc,
    author="nexB Inc. and others",
    author_email="info@aboutcode.org",
    url="https://github.com/nexB/vulnerablecode",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Utilities",
    ],
    keywords=[
        "open source",
        "vulnerability",
        "package",
    ],
    install_requires=requirements,
)
