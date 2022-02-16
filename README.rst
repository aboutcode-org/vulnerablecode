VulnerableCode
==============

|Build Status| |License| |Python 3.8| |stability-wip| |Gitter chat|


.. |Build Status| image:: https://github.com/nexB/vulnerablecode/actions/workflows/main.yml/badge.svg?branch=main
   :target: https://github.com/nexB/vulnerablecode/actions?query=workflow%3ACI
.. |License| image:: https://img.shields.io/badge/License-Apache%202.0-blue.svg
   :target: https://opensource.org/licenses/Apache-2.0
.. |Python 3.8| image:: https://img.shields.io/badge/python-3.8-blue.svg
   :target: https://www.python.org/downloads/release/python-380/
.. |stability-wip| image:: https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg
.. |Gitter chat| image:: https://badges.gitter.im/gitterHQ/gitter.png
   :target: https://gitter.im/aboutcode-org/vulnerablecode


VulnerableCode is a free and open database of FOSS software package
vulnerabilities and the tools to create and keep the data current.

It is made by the FOSS community to improve and secure the open source software
ecosystem.

.. image:: README.gif

Getting started
---------------

Run with Docker
^^^^^^^^^^^^^^^^

.. code-block:: bash

    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make envfile
    docker-compose build
    docker-compose up
    docker-compose run vulnerablecode ./manage.py import --list

At this point, the VulnerableCode app should be running at port ``8000`` on your Docker host.

Local development installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    sudo apt-get install \
        python3-venv python3-dev postgresql libpq-dev build-essential
    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make dev envfile postgres
    make test
    make run

At this point, the VulnerableCode app should be running at port ``8000`` on your machine.

Populate VulnerableCode data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To run all importers and improvers use:

.. code-block:: bash

   ./manage.py import --all
   ./manage.py improve --all

Read more about VulnerableCode here: https://vulnerablecode.readthedocs.org/
