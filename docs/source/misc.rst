.. _miscellaneous:

Miscellaneous
==============

Continuous periodic Data import
-------------------------------


If you want to run the import periodically, you can use a systemd timer.
Here is an example::

    $ cat ~/.config/systemd/user/vulnerablecode.service

    [Unit]
    Description=Run VulnerableCode importers

    [Service]
    Type=oneshot
    ExecStart=/path/to/venv/bin/python /path/to/vulnerablecode/manage.py import --all

    $ cat ~/.config/systemd/user/vulnerablecode.timer

    [Unit]
    Description=Periodically run VulnerableCode importers

    [Timer]
    OnCalendar=daily

    [Install]
    WantedBy=multi-user.target


Start this timer with::

    systemctl --user daemon-reload
    systemctl --user start vulnerablecode.timer

