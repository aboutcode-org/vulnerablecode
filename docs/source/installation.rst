.. _installation:

Installation
============

.. warning::
   VulnerableCode is going through a major structural change and the installations are likely to not produce enough results. This is being tracked in https://github.com/nexB/vulnerablecode/issues/597

Welcome to **VulnerableCode** installation guide! This guide describes how to install
VulnerableCode on various platforms.
Please read and follow the instructions carefully to ensure your installation is
functional and smooth.

The **preferred VulnerableCode installation** is to :ref:`run_with_docker` as this is
the simplest to setup and get started.
Running VulnerableCode with Docker **guarantees the availability of all features** with the
**minimum configuration** required.
This installation **works across all Operating Systems**.

Alternatively, you can install VulnerableCode locally as a development server with some
limitations and caveats. Refer to the :ref:`local_development_installation` section.

.. _run_with_docker:

Run with Docker
---------------

Get Docker
^^^^^^^^^^

The first step is to download and **install Docker on your platform**.
Refer to Docker documentation and choose the best installation
path for your system: `Get Docker <https://docs.docker.com/get-docker/>`_.

Build the Image
^^^^^^^^^^^^^^^

VulnerableCode is distributed with ``Dockerfile`` and ``docker-compose.yml`` files
required for the creation of the Docker image.

Clone the git `VulnerableCode repo <https://github.com/nexB/vulnerablecode>`_,
create an environment file, and build the Docker image:

.. code-block:: bash

    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make envfile
    docker-compose build

.. note::

    The image will need to be re-built when the VulnerableCode app source code is
    modified or updated via
    ``docker-compose build --no-cache vulnerablecode``

Run the App
^^^^^^^^^^^

**Run your image** as a container

.. code-block:: bash

    docker-compose up


At this point, the VulnerableCode app should be running at port ``8000`` on your Docker host.
Go to http://localhost:8000/ on a web browser to access the web UI.
Optionally, you can set ``NGINX_PORT`` environment variable in your shell or in the `.env` file
to run on a different port than 8000.

.. note::

    To access a dockerized VulnerableCode app from a remote location, the ``ALLOWED_HOSTS``
    setting need to be provided in your ``docker.env`` file::

        ALLOWED_HOSTS=.domain.com,127.0.0.1

    Refer to `Django ALLOWED_HOSTS settings <https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts>`_
    for more details.

.. warning::

   Serving VulnerableCode on a network could lead to security issues and there
   are several steps that may be needed to secure such a deployment.
   Currently, this is not recommendend.

Execute a Command
^^^^^^^^^^^^^^^^^

You can execute a one of ``manage.py`` commands through the Docker command line
interface, for example

.. code-block:: bash

    docker-compose run vulnerablecode ./manage.py import --list

.. note::
    Refer to the :ref:`command_line_interface` section for the full list of commands.

Alternatively, you can connect to the Docker container ``bash`` and run commands
from there

.. code-block:: bash

    docker-compose run vulnerablecode bash
    ./manage.py import --list


.. _local_development_installation:

Local development installation
------------------------------

Supported Platforms
^^^^^^^^^^^^^^^^^^^

**VulnerableCode* has been tested and is supported on the following operating systems:

    #. **Debian-based** Linux distributions
    #. **macOS** 12.1 and up

.. warning::
     On **Windows** VulnerableCode can **only** be :ref:`run_with_docker` and is not supported.

Pre-installation Checklist
^^^^^^^^^^^^^^^^^^^^^^^^^^

Before you install VulnerableCode, make sure you have the following prerequisites:

 * **Python: 3.8* found at https://www.python.org/downloads/
 * **Git**: most recent release available at https://git-scm.com/
 * **PostgreSQL**: release 9 or later found at https://www.postgresql.org/ or
   https://postgresapp.com/ on macOS

.. _system_dependencies:

System Dependencies
^^^^^^^^^^^^^^^^^^^

In addition to the above pre-installation checklist, there might be some OS-specific
system packages that need to be installed before installing VulnerableCode.

On **Debian-based distros**, several **system packages are required** by VulnerableCode.
Make sure those are installed

.. code-block:: bash

    sudo apt-get install \
        python3-venv python3-dev postgresql libpq-dev build-essential

Clone and Configure
^^^^^^^^^^^^^^^^^^^

Clone the `VulnerableCode Git repository <https://github.com/nexB/vulnerablecode>`_::

    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode

Install the required dependencies::

    make dev

.. note::

    You can specify the Python version during the ``make dev`` step using the following
    command::

             make dev PYTHON_EXE=python3.8.10

    When ``PYTHON_EXE`` is not specified, by default, the ``python3`` executable is
    used.

Create an environment file::

    make envfile

Database
^^^^^^^^

**PostgreSQL** is the preferred database backend and should always be used on
production servers.

* Create the PostgreSQL user, database, and table with::

    make postgres

.. note::
    You can also use a **SQLite** database for local development as a single user
    with::

        make sqlite

.. warning::
    Choosing SQLite over PostgreSQL has some caveats. Check this `link
    <https://docs.djangoproject.com/en/dev/ref/databases/#sqlite-notes>`_
    for more details.

Tests
^^^^^

You can validate your VulnerableCode installation by running the tests suite::

    make test

Web Application
^^^^^^^^^^^^^^^

A web application is available to create and manage your projects from a browser;
you can start the local webserver and access the app with::

    make run

Then open your web browser and visit: http://127.0.0.1:8000/ to access the web
application.

.. warning::
    This setup is **not suitable for deployments** and **only supported for local
    development**.

An overview of the web application usage is available at :ref:`user_interface`.

Upgrading
^^^^^^^^^

If you already have the VulnerableCode repo cloned, you can upgrade to the latest version
with::

    cd vulnerablecode
    git pull
    make dev
    make migrate

Using Nix
-----------

You can install VulnerableCode with `Nix <https://nixos.org/download.html>`__
(`Flake <https://nixos.wiki/wiki/Flakes>`__ support is needed)::

    cd etc/nix
    nix-shell -p nixFlakes --run "nix --print-build-logs flake check " # build & run tests

There are several options to use the Nix version::

    # Enter an interactive environment with all dependencies set up.
    cd etc/nix
    nix develop
    > ../../manage.py ... # invoke the local checkout
    > vulnerablecode-manage.py ... # invoke manage.py as installed in the nix store

    # Test the import prodecure using the Nix version.
    etc/nix/test-import-using-nix.sh --all # import everything
    # Test the import using the local checkout.
    INSTALL_DIR=. etc/nix/test-import-using-nix.sh ruby # import ruby only


**Keeping the Nix setup in sync**

The Nix installation uses `mach-nix <https://github.com/DavHau/mach-nix>`__ to
handle Python dependencies because some dependencies are currently not available
as Nix packages. All Python dependencies are automatically fetched from
``./requirements.txt``. If the ``mach-nix``-based installation fails, you might
need to update ``mach-nix`` itself and the `pypi-deps-db
<https://github.com/DavHau/pypi-deps-db>`_ version in use (see
``etc/nix/flake.nix:inputs.machnix`` and ``machnixFor.pypiDataRev``).

Non-Python dependencies are curated in::

    etc/nix/flake.nix:vulnerablecode.propagatedBuildInputs
