===============
VulnerableCode
===============

|Build Status| |Code License| |Data License| |Python 3.8+| |stability-wip| |Gitter chat|


.. |Build Status| image:: https://github.com/nexB/vulnerablecode/actions/workflows/main.yml/badge.svg?branch=main
   :target: https://github.com/nexB/vulnerablecode/actions?query=workflow%3ACI
.. |Code License| image:: https://img.shields.io/badge/Code%20License-Apache--2.0-green.svg
   :target: https://opensource.org/licenses/Apache-2.0
.. |Data License| image:: https://img.shields.io/badge/Data%20License-CC--BY--SA--4.0-green.svg
   :target: https://creativecommons.org/licenses/by-sa/4.0/legalcode 
.. |Python 3.8+| image:: https://img.shields.io/badge/python-3.8+-green.svg
   :target: https://www.python.org/downloads/release/python-380/
.. |stability-wip| image:: https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg
.. |Gitter chat| image:: https://badges.gitter.im/gitterHQ/gitter.png
   :target: https://gitter.im/aboutcode-org/vulnerablecode


VulnerableCode is a free and open database of open source software package
vulnerabilities **because open source software vulnerabilities data and tools
should be free and open source themselves**:

we are trying to change this and evolve the status quo in a few other areas!

- Vulnerability databases have been **traditionally proprietary** even though they
  are mostly about free and open source software. 

- Vulnerability databases also often contain a lot of lesser value data which
  means a lot of false positive signals that require extensive expert reviews.

- Vulnerability databases are also mostly about vulnerabilities first and software
  package second, making it difficult to find if and when a vulnerability applies
  to a piece of code. VulnerableCode focus is on software package first where
  a Package URL is a key and natural identifier for packages; this is making it
  easier to find a package and whether it is vulnerable.

Package URL themselves were designed first in ScanCode and VulnerableCode
and are now a de-facto standard for vulnerability management and package references.

See https://github.com/package-url/purl-spec

The VulnerableCode project is a FOSS community resource to help improve the
security of the open source software ecosystem and its users at large.

VulnerableCode consists of a database and the tools to collect, refine and keep
the database current. 

.. warning::
    VulnerableCode is under active development and is not yet fully
    usable.

Read more about VulnerableCode https://vulnerablecode.readthedocs.org/

VulnerableCode is financially supported by NLnet, nexB, Google (through the
GSoC) and the active contributions of several volunteers.

VulnerableCode tech stack is Python, Django, PostgreSQL, nginx and Docker and
several libraries.


Getting started
---------------

Run with Docker
^^^^^^^^^^^^^^^^

First install docker and docker-compose, then run::

    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make envfile
    docker-compose build
    docker-compose up -d
    docker-compose run vulnerablecode ./manage.py import --list

Then run an importer for nginx advisories (which is small)::

    docker-compose exec vulnerablecode ./manage.py import vulnerabilities.importers.nginx.NginxImporter
    docker-compose exec vulnerablecode ./manage.py improve --all

At this point, the VulnerableCode app and API should be up and running with
some data at http://localhost


Populate VulnerableCode database
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

VulnerableCode data collection works in two steps: importing data from multiple
sources and then refining and improving how package and software vulnerabilities
are related.

To run all importers and improvers use this::

   ./manage.py import --all
   ./manage.py improve --all


Local development installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On a Debian system, use this::

    sudo apt-get install  python3-venv python3-dev postgresql libpq-dev build-essential
    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make dev envfile postgres
    make test
    ./manage.py import vulnerabilities.importers.nginx.NginxImporter
    ./manage.py improve --all
    make run

At this point, the VulnerableCode app and API is up at http://127.0.0.1:8001/

Interface
^^^^^^^^^^


VulnerableCode comes with a minimal web UI:

.. image:: vulnerablecode-ui.png

And a JSON API and its minimal web documentation:

.. image:: vulnerablecode-json-api.png
.. image:: vulnerablecode-api-doc.png


License
^^^^^^^^^^

Copyright (c) nexB Inc. and others. All rights reserved.
VulnerableCode is a trademark of nexB Inc.
SPDX-License-Identifier: Apache-2.0 AND CC-BY-SA-4.0
VulnerableCode software is licensed under the Apache License version 2.0.
VulnerableCode data is licensed collectively under CC-BY-SA-4.0.
See https://www.apache.org/licenses/LICENSE-2.0 for the license text.
See https://creativecommons.org/licenses/by-sa/4.0/legalcode for the license text.

See https://github.com/nexB/vulnerablecode for support or download. 
See https://aboutcode.org for more information about nexB OSS projects.
