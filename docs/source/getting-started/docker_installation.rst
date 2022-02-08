.. _docker_image:

Docker image
============

Get Docker
----------

The first step is to download and install Docker on your platform.
Refer to the following Docker documentation and choose the best installation
path for you: `Get Docker <https://docs.docker.com/get-docker/>`_

Build the Image
---------------

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

Run the Image
-------------

Run your image as a container

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
    for documentation.

.. warning::

   Serving VulnerableCode on a network could lead to security issues and there
   are several steps that may be needed to secure such a deployment.
   Currently, this is not recommendend.


Invoke the importers
--------------------

Connect to the Docker container ``bash``.
From here you can access ``manage.py`` and run management commands
to import data as specified in the `Data import <../README.rst#data-import>`_ section and
run commands for the importers from there

For example:

.. code-block:: bash

    docker-compose exec vulnerablecode bash
    ./manage.py import --list


