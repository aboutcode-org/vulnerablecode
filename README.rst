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


.. pull-quote::
   **Warning**

   VulnerableCode is under active development and is not yet fully
   usable.


Read more about VulnerableCode https://vulnerablecode.readthedocs.org/

VulnerableCode tech stack is Python, Django, PostgreSQL, nginx and Docker and
several libraries.


Getting started
===============

Run with Docker
---------------

First install docker, then run

.. code:: bash

    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make envfile
    docker compose build
    docker compose up -d
    docker compose run vulnerablecode ./manage.py import --list

Then run an importer for nginx advisories (which is small)

.. code:: bash

    docker compose exec vulnerablecode ./manage.py import nginx_importer
    docker compose exec vulnerablecode ./manage.py improve --all

At this point, the VulnerableCode app and API should be up and running with
some data at http://localhost


Populate VulnerableCode database
--------------------------------

VulnerableCode data collection works in two steps: importing data from multiple
sources and then refining and improving how package and software vulnerabilities
are related.

To run all importers and improvers use this

.. code:: bash

   ./manage.py import --all

.. code:: bash

   ./manage.py improve --all


Local development installation
------------------------------

On a Debian system, use this

.. code:: bash

    sudo apt-get install  python3-venv python3-dev postgresql libpq-dev build-essential
    git clone https://github.com/nexB/vulnerablecode.git && cd vulnerablecode
    make dev envfile postgres
    make test
    source venv/bin/activate
    ./manage.py import nginx_importer
    ./manage.py improve --all
    make run

At this point, the VulnerableCode app and API is up at http://127.0.0.1:8001/


License
========

Copyright (c) nexB Inc. and others. All rights reserved.

VulnerableCode is a trademark of nexB Inc.

SPDX-License-Identifier: Apache-2.0 AND CC-BY-SA-4.0

VulnerableCode software is licensed under the Apache License version 2.0.

VulnerableCode data is licensed collectively under CC-BY-SA-4.0.

See https://www.apache.org/licenses/LICENSE-2.0 for the license text.

See https://creativecommons.org/licenses/by-sa/4.0/legalcode for the license text.

See https://github.com/nexB/vulnerablecode for support or download. 

See https://aboutcode.org for more information about nexB OSS projects.


Acknowledgements, Funding, Support and Sponsoring
=================================================

This project is funded, supported and sponsored by:

- Generous support and contributions from users like you!
- the European Commission NGI programme
- the NLnet Foundation 
- the Swiss State Secretariat for Education, Research and Innovation (SERI)
- Google, including the Google Summer of Code and the Google Seasons of Doc programmes
- Mercedes-Benz Group
- Microsoft and Microsoft Azure
- AboutCode ASBL
- nexB Inc. 



|europa|   |dgconnect| 

|ngi|   |nlnet|   

|aboutcode|  |nexb|



This project was funded through the NGI0 PET Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 825310.

|ngizeropet|  https://nlnet.nl/project/VulnerableCode/


This project was funded through the NGI0 Discovery Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 825322.

|ngidiscovery| https://nlnet.nl/project/vulnerabilitydatabase/


This project was funded through the NGI0 Core Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 101092990.

|ngizerocore| https://nlnet.nl/project/VulnerableCode-enhancements/


This project is funded through the NGI0 Entrust Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 101069594.

|ngizeroentrust| https://nlnet.nl/project/FederatedSoftwareMetadata/


This project was funded through the NGI0 Commons Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 101135429. Additional
funding is made available by the Swiss State Secretariat for Education, Research and Innovation
(SERI). 

|ngizerocommons| |swiss| https://nlnet.nl/project/FederatedCodeNext/

This project was funded through the NGI0 Entrust Fund, a fund established by NLnet with financial
support from the European Commission's Next Generation Internet programme, under the aegis of DG
Communications Networks, Content and Technology under grant agreement No 101069594. 

|ngizeroentrust| https://nlnet.nl/project/CRAVEX/



.. |nlnet| image:: https://nlnet.nl/logo/banner.png
    :target: https://nlnet.nl
    :height: 50
    :alt: NLnet foundation logo

.. |ngi| image:: https://ngi.eu/wp-content/uploads/thegem-logos/logo_8269bc6efcf731d34b6385775d76511d_1x.png
    :target: https://ngi.eu35
    :height: 50
    :alt: NGI logo

.. |nexb| image:: https://nexb.com/wp-content/uploads/2022/04/nexB.svg
    :target: https://nexb.com
    :height: 30
    :alt: nexB logo

.. |europa| image:: https://ngi.eu/wp-content/uploads/sites/77/2017/10/bandiera_stelle.png
    :target: http://ec.europa.eu/index_en.htm
    :height: 40
    :alt: Europa logo

.. |aboutcode| image:: https://aboutcode.org/wp-content/uploads/2023/10/AboutCode.svg
    :target: https://aboutcode.org/
    :height: 30
    :alt: AboutCode logo

.. |swiss| image:: https://www.sbfi.admin.ch/sbfi/en/_jcr_content/logo/image.imagespooler.png/1493119032540/logo.png
    :target: https://www.sbfi.admin.ch/sbfi/en/home/seri/seri.html
    :height: 40
    :alt: Swiss logo

.. |dgconnect| image:: https://commission.europa.eu/themes/contrib/oe_theme/dist/ec/images/logo/positive/logo-ec--en.svg
    :target: https://commission.europa.eu/about-european-commission/departments-and-executive-agencies/communications-networks-content-and-technology_en
    :height: 40
    :alt: EC DG Connect logo

.. |ngizerocore| image:: https://nlnet.nl/image/logos/NGI0_tag.svg
    :target: https://nlnet.nl/core
    :height: 40
    :alt: NGI Zero Core Logo

.. |ngizerocommons| image:: https://nlnet.nl/image/logos/NGI0_tag.svg
    :target: https://nlnet.nl/commonsfund/
    :height: 40
    :alt: NGI Zero Commons Logo

.. |ngizeropet| image:: https://nlnet.nl/image/logos/NGI0PET_tag.svg
    :target: https://nlnet.nl/PET
    :height: 40
    :alt: NGI Zero PET logo

.. |ngizeroentrust| image:: https://nlnet.nl/image/logos/NGI0Entrust_tag.svg
    :target: https://nlnet.nl/entrust
    :height: 38
    :alt: NGI Zero Entrust logo

.. |ngiassure| image:: https://nlnet.nl/image/logos/NGIAssure_tag.svg
    :target: https://nlnet.nl/image/logos/NGIAssure_tag.svg
    :height: 32
    :alt: NGI Assure logo

.. |ngidiscovery| image:: https://nlnet.nl/image/logos/NGI0Discovery_tag.svg
    :target: https://nlnet.nl/discovery/
    :height: 40
    :alt: NGI Discovery logo
