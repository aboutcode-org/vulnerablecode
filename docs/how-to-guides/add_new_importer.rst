Adding a new Importer to VulnerableCode
=======================================


This tutorial contains all the things one should know to quickly
implement an Importer.

The Building Blocks A.K.A Prerequisites

(1) ``PackageURL`` : VulnerableCode decodes ``PackageURL`` objects and
    writes them into DB. PackageURL's constructor requires 3 arguments
    to be instantiated these are :

::

        name
        type
        version

**Example usage:**

.. code:: python

    from packageurl import PackageURL
    p1 = PackageURL(name="ffmpeg",type="deb",version="1.2.3")


(2) ``Advisory``: ``Advisory`` is an intermediate data-format, it is
    expected, that your code converts the data into these ``Advisory``
    objects. The following is the re-paste of definition of ``Advisory``
    data class from ``vulnerabilities/data_source.py`` for reference.

.. code:: python

    class Advisory:
        summary: str
        impacted_package_urls: Iterable[PackageURL]
        resolved_package_urls: Iterable[PackageURL] = dataclasses.field(default_factory=list)
        reference_urls: Sequence[str] = dataclasses.field(default_factory=list)
        reference_ids: Sequence[str] = dataclasses.field(default_factory=list)
        cve_id: Optional[str] = None


Steps to build an Importer
--------------------------

* **Register an Importer:**

To do this go to ``vulnerabilites/importer_yielder.py``, in the ``IMPORTER_REGISTRY``
list add a dictionary with following data 

.. code:: python

    {
        'name': <your_importer_name> ,
        'license': '',
        'last_run': None,
        'data_source': <your_data_source_name>,
        'data_source_cfg': {},
    }

  
**Don't forget to replace <your_importer_name> and <your_data_source_name> with
appropriate strings**

For this example let's consider `<your_data_source_name> = "ExampleDataSource"`.
If you know the license of the data you are importing, assign the license field
equal to the license of the data in the  ``add_<your_importer_name>_importer``
method of the migration script.

* **Create a data source** : 

  - Go to ``vulnerabilities/importers`` , create a python script, let's call it ``my_importer.py``

  - Implement the ``updated_advisories`` method.

  A minimal ``my_importer`` would look like :

.. code:: python

    from typing import Set
    
    from packageurl import PackageURL
    import requests
    
    from vulnerabilities.data_source import Advisory
    from vulnerabilities.data_source import DataSource
    
    class ExampleDataSource(DataSource):
        #This method must be implemented
        def updated_advisories(self)-> Set[Advisory]:
            raw_data = self.fetch()
            advisories = self.to_advisories(raw_data)
            return self.batch_advisories(advisories)
            
        #Optional Method, but it is recommended to have fetching separated  
        def fetch(self):
            return requests.get("http://examplesecurity.org/api/json").json()
            
        #Optional Method  
        @staticmethod
        def to_advisories(json_response:dict) -> Set[Advisory]:
            advisories = []
            for entry in json_response:
                pkg_name = entry['name']
                vuln_pkg_versions = entry['affected']['versions']
                safe_pkg_versions = entry['unaffected']['versions']
                pkg_type = "deb"
                cve_id = entry['cve_id']
                safe_purls ={ PackageURL(name=pkg_name,
                    type=pkg_type,
                    version=version) 
                    for version in safe_pkg_versions}
                vuln_purls= {PackageURL(name=pkg_name,
                    type=pkg_type,
                    version=version) 
                    for version in vuln_pkg_versions}
                     
                     
                advisory = Advisory(cve_id=cve_id,summary='',impacted_package_urls=vuln_purls,resolved_package_urls=safe_purls)
                advisories.append(advisory)
            return advisories
    

Finally register this ``ExampleDataSource`` in
``vulnerabilities/importers/__init__.py`` by adding the following line

.. code:: python

    from vulnerabilities.importers.my_importer import ExampleDataSource

Done, congrats on writing your new importer.Test it via

::

    ./manage.py migrate
    ./manage.py import my_importer