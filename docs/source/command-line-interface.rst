.. _command_line_interface:

Command Line Interface
======================

The main entry point is the Django :guilabel:`manage.py` management command script.

``$ ./manage.py --help``
------------------------

Lists all sub-commands available, including Django built-in commands.
VulnerableCode's own commands are listed under the ``[vulnerabilities]`` section::

    $ ./manage.py --help
    ...
    [vulnerabilities]
        import
        improve
        purl2cpe


``$ ./manage.py <subcommand> --help``
---------------------------------------

Displays help for the provided sub-command.

For example::

    $ ./manage.py import --help
    usage: manage.py import [-h] [--list] [--all] [--version] [-v {0,1,2,3}]
                            [--settings SETTINGS] [--pythonpath PYTHONPATH]
                            [--traceback] [--no-color] [--force-color]
                            [--skip-checks]
                            [sources [sources ...]]

    Import vulnerability data

    positional arguments:
      sources               Fully qualified importer name to run


``$ ./manage.py import <importer-name>``
------------------------------------------

Import vulnerability data using the given importer name.

Other variations:

* ``--list`` List all available importers
* ``--all`` Run all available importers


``$ ./manage.py improve <improver-name>``
------------------------------------------

Improve the imported vulnerability data using the given improver name.

Other variations:

* ``--list`` List all available improvers
* ``--all`` Run all available improvers



``$ ./manage.py purl2cpe --destination <directory``
------------------------------------------

Dump a mapping of CPEs to PURLs grouped by vulnerability in the ``destination``
directory.


Other variations:

* ``--limit`` Limit the number of processed vulnerabilities

