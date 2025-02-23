Package URL specification v1.0.X
================================

The Package URL core specification defines a versioned and formalized format,
syntax, and rules used to represent and validate ``purl``.

A ``purl`` or package URL is an attempt to standardize existing approaches to
reliably identify and locate software packages.

A ``purl`` is a URL string used to identify and locate a software package in a
mostly universal and uniform way across programming languages, package managers,
packaging conventions, tools, APIs and databases.

Such a package URL is useful to reliably reference the same software package
using a simple and expressive syntax and conventions based on familiar URLs.

See <PURL-TYPES.rst>_ for known type definitions.

Check also this short ``purl`` presentation (with video) at FOSDEM 2018
https://fosdem.org/2018/schedule/event/purl/ for an overview.


``purl`` stands for **package URL**.

A ``purl`` is a URL composed of seven components::

    scheme:type/namespace/name@version?qualifiers#subpath

Components are separated by a specific character for unambiguous parsing.

The definition for each components is:

- **scheme**: this is the URL scheme with the constant value of "pkg". One of
  the primary reason for this single scheme is to facilitate the future official
  registration of the "pkg" scheme for package URLs. Required.
- **type**: the package "type" or package "protocol" such as maven, npm, nuget,
  gem, pypi, etc. Required.
- **namespace**: some name prefix such as a Maven groupid, a Docker image owner,
  a GitHub user or organization. Optional and type-specific.
- **name**: the name of the package. Required.
- **version**: the version of the package. Optional.
- **qualifiers**: extra qualifying data for a package such as an OS,
  architecture, a distro, etc. Optional and type-specific.
- **subpath**: extra subpath within a package, relative to the package root.
  Optional.


Components are designed such that they form a hierarchy from the most significant
on the left to the least significant components on the right.


A ``purl`` must NOT contain a URL Authority i.e. there is no support for
``username``, ``password``, ``host`` and ``port`` components. A ``namespace`` segment may
sometimes look like a ``host`` but its interpretation is specific to a ``type``.


Some ``purl`` examples
~~~~~~~~~~~~~~~~~~~~~~

::

    pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c
    pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
    pkg:gem/ruby-advisory-db-check@0.12.4
    pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c
    pkg:golang/google.golang.org/genproto#googleapis/api/annotations
    pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources
    pkg:npm/foobar@12.3.1
    pkg:nuget/EnterpriseLibrary.Common@6.0.1304
    pkg:pypi/django@1.11.1
    pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25


A ``purl`` is a URL
~~~~~~~~~~~~~~~~~~~

- A ``purl`` is a valid URL and URI that conforms to the URL definitions or
  specifications at:

  - https://tools.ietf.org/html/rfc3986
  - https://en.wikipedia.org/wiki/URL#Syntax
  - https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Syntax
  - https://url.spec.whatwg.org/

- This is a valid URL because it is a locator even though it has no Authority
  URL component: each ``type`` has a default repository location when defined.

- The ``purl`` components are mapped to these URL components:

  - ``purl`` ``scheme``: this is a URL ``scheme`` with a constant value: ``pkg``
  - ``purl`` ``type``, ``namespace``, ``name`` and ``version`` components: these are
    collectively mapped to a URL ``path``
  - ``purl`` ``qualifiers``: this maps to a URL ``query``
  - ``purl`` ``subpath``: this is a URL ``fragment``
  - In a ``purl`` there is no support for a URL Authority (e.g. NO
    ``username``, ``password``, ``host`` and ``port`` components).

- Special URL schemes as defined in https://url.spec.whatwg.org/ such as
  ``file://``, ``https://``, ``http://`` and ``ftp://`` are NOT valid ``purl`` types.
  They are valid URL or URI schemes but they are not ``purl``.
  They may be used to reference URLs in separate attributes outside of a ``purl``
  or in a ``purl`` qualifier.

- Version control system (VCS) URLs such ``git://``, ``svn://``, ``hg://`` or as
  defined in Python pip or SPDX download locations are NOT valid ``purl`` types.
  They are valid URL or URI schemes but they are not ``purl``.
  They are a closely related, compact and uniform way to reference VCS URLs.
  They may be used as references in separate attributes outside of a ``purl`` or
  in a ``purl`` qualifier.


Rules for each ``purl`` component
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``purl`` string is an ASCII URL string composed of seven components.

Some components are allowed to use other characters beyond ASCII: these
components must then be UTF-8-encoded strings and percent-encoded as defined in
the "Character encoding" section.

The rules for each component are:

- **scheme**:

  - The ``scheme`` is a constant with the value "pkg".
  - The ``scheme`` MUST be followed by an unencoded colon ':'.
  - ``purl`` parsers MUST accept URLs where the ``scheme`` and colon ':' are
    followed by one or more slash '/' characters, such as 'pkg://', and MUST
    ignore and remove all such '/' characters.


- **type**:

  - The package ``type`` MUST be composed only of ASCII letters and numbers,
    '.', '+' and '-' (period, plus, and dash).
  - The ``type`` MUST start with an ASCII letter.
  - The ``type`` MUST NOT be percent-encoded.
  - The ``type`` is case insensitive. The canonical form is lowercase.


- **namespace**:

  - The optional ``namespace`` contains zero or more segments, separated by slash
    '/'
  - Leading and trailing slashes '/' are not significant and should be stripped
    in the canonical form. They are not part of the ``namespace``
  - Each ``namespace`` segment must be a percent-encoded string
  - When percent-decoded, a segment:

    - must not contain a '/'
    - must not be empty

  - A URL host or Authority must NOT be used as a ``namespace``. Use instead a
    ``repository_url`` qualifier. Note however that for some types, the
    ``namespace`` may look like a host.


- **name**:

  - The ``name`` is prefixed by a '/' separator when the ``namespace`` is not empty
  - This '/' is not part of the ``name``
  - A ``name`` must be a percent-encoded string


- **version**:

  - The ``version`` is prefixed by a '@' separator when not empty
  - This '@' is not part of the ``version``
  - A ``version`` must be a percent-encoded string

  - A ``version`` is a plain and opaque string. Some package ``types`` use versioning
    conventions such as SemVer for NPMs or NEVRA conventions for RPMS. A ``type``
    may define a procedure to compare and sort versions, but there is no
    reliable and uniform way to do such comparison consistently.


- **qualifiers**:

  - The ``qualifiers`` string is prefixed by a '?' separator when not empty
  - This '?' is not part of the ``qualifiers``
  - This is a query string composed of zero or more ``key=value`` pairs each
    separated by a '&' ampersand. A ``key`` and ``value`` are separated by the equal
    '=' character
  - These '&' are not part of the ``key=value`` pairs.
  - ``key`` must be unique within the keys of the ``qualifiers`` string
  - ``value`` cannot be an empty string: a ``key=value`` pair with an empty ``value``
    is the same as no key/value at all for this key
  - For each pair of ``key`` = ``value``:

    - The ``key`` must be composed only of ASCII letters and numbers, '.', '-' and
      '_' (period, dash and underscore)
    - A ``key`` cannot start with a number
    - A ``key`` must NOT be percent-encoded
    - A ``key`` is case insensitive. The canonical form is lowercase
    - A ``key`` cannot contain spaces
    - A ``value`` must be a percent-encoded string
    - The '=' separator is neither part of the ``key`` nor of the ``value``


- **subpath**:

  - The ``subpath`` string is prefixed by a '#' separator when not empty
  - This '#' is not part of the ``subpath``
  - The ``subpath`` contains zero or more segments, separated by slash '/'
  - Leading and trailing slashes '/' are not significant and SHOULD be stripped
    in the canonical form
  - Each ``subpath`` segment MUST be a percent-encoded string
  - When percent-decoded, a segment:
    - MUST NOT contain a '/'
    - MUST NOT be any of '..' or '.'
    - MUST NOT be empty
  - The ``subpath`` MUST be interpreted as relative to the root of the package


Character encoding
~~~~~~~~~~~~~~~~~~

For clarity and simplicity a ``purl`` is always an ASCII string. To ensure that
there is no ambiguity when parsing a ``purl``, separator characters and non-ASCII
characters must be UTF-encoded and then percent-encoded as defined at::

    https://en.wikipedia.org/wiki/Percent-encoding

Use these rules for percent-encoding and decoding ``purl`` components:

- the ``type`` must NOT be encoded and must NOT contain separators

- the '#', '?', '@' and ':' characters must NOT be encoded when used as
  separators. They may need to be encoded elsewhere

- the ':' ``scheme`` and ``type`` separator does not need to and must NOT be encoded.
  It is unambiguous unencoded everywhere

- the '/' used as ``type``/``namespace``/``name`` and ``subpath`` segments separator
  does not need to and must NOT be percent-encoded. It is unambiguous unencoded
  everywhere

- the '@' ``version`` separator must be encoded as ``%40`` elsewhere
- the '?' ``qualifiers`` separator must be encoded as ``%3F`` elsewhere
- the '=' ``qualifiers`` key/value separator must NOT be encoded
- the '#' ``subpath`` separator must be encoded as ``%23`` elsewhere

- All non-ASCII characters must be encoded as UTF-8 and then percent-encoded

It is OK to percent-encode ``purl`` components otherwise except for the ``type``.
Parsers and builders must always percent-decode and percent-encode ``purl``
components and component segments as explained in the "How to parse" and "How to
build" sections.


How to build ``purl`` string from its components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Building a ``purl`` ASCII string works from left to right, from ``type`` to
``subpath``.

Note: some extra type-specific normalizations are required.
See the "Known types section" for details.

To build a ``purl`` string from its components:


- Start a ``purl`` string with the "pkg:" ``scheme`` as a lowercase ASCII string

- Append the ``type`` string to the ``purl`` as an unencoded lowercase ASCII string

  - Append '/' to the ``purl``

- If the ``namespace`` is not empty:

  - Strip the ``namespace`` from leading and trailing '/'
  - Split on '/' as segments
  - Apply type-specific normalization to each segment if needed
  - UTF-8-encode each segment if needed in your programming language
  - Percent-encode each segment
  - Join the segments with '/'
  - Append this to the ``purl``
  - Append '/' to the ``purl``
  - Strip the ``name`` from leading and trailing '/'
  - Apply type-specific normalization to the ``name`` if needed
  - UTF-8-encode the ``name`` if needed in your programming language
  - Append the percent-encoded ``name`` to the ``purl``

- If the ``namespace`` is empty:

  - Apply type-specific normalization to the ``name`` if needed
  - UTF-8-encode the ``name`` if needed in your programming language
  - Append the percent-encoded ``name`` to the ``purl``

- If the ``version`` is not empty:

  - Append '@' to the ``purl``
  - UTF-8-encode the ``version`` if needed in your programming language
  - Append the percent-encoded version to the ``purl``

- If the ``qualifiers`` are not empty and not composed only of key/value pairs
  where the ``value`` is empty:

  - Append '?' to the ``purl``
  - Build a list from all key/value pair:

    - Discard any pair where the ``value`` is empty.
    - UTF-8-encode each ``value`` if needed in your programming language
    - If the ``key`` is ``checksums`` and this is a list of ``checksums`` join this
      list with a ',' to create this qualifier ``value``
    - Create a string by joining the lowercased ``key``, the equal '=' sign and
      the percent-encoded ``value`` to create a qualifier

  - Sort this list of qualifier strings lexicographically
  - Join this list of qualifier strings with a '&' ampersand
  - Append this string to the ``purl``

- If the ``subpath`` is not empty and not composed only of empty, '.' and '..'
  segments:

  - Append '#' to the ``purl``
  - Strip the ``subpath`` from leading and trailing '/'
  - Split this on '/' as segments
  - Discard empty, '.' and '..' segments
  - Percent-encode each segment
  - UTF-8-encode each segment if needed in your programming language
  - Join the segments with '/'
  - Append this to the ``purl``


How to parse a ``purl`` string in its components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parsing a ``purl`` ASCII string into its components works from right to left,
from ``subpath`` to ``type``.

Note: some extra type-specific normalizations are required.
See the "Known types section" for details.

To parse a ``purl`` string in its components:

- Split the ``purl`` string once from right on '#'

  - The left side is the ``remainder``
  - Strip the right side from leading and trailing '/'
  - Split this on '/'
  - Discard any empty string segment from that split
  - Percent-decode each segment
  - Discard any '.' or '..' segment from that split
  - UTF-8-decode each segment if needed in your programming language
  - Join segments back with a '/'
  - This is the ``subpath``

- Split the ``remainder`` once from right on '?'

  - The left side is the ``remainder``
  - The right side is the ``qualifiers`` string
  - Split the ``qualifiers`` on '&'. Each part is a ``key=value`` pair
  - For each pair, split the ``key=value`` once from left on '=':

    - The ``key`` is the lowercase left side
    - The ``value`` is the percent-decoded right side
    - UTF-8-decode the ``value`` if needed in your programming language
    - Discard any key/value pairs where the value is empty
    - If the ``key`` is ``checksums``, split the ``value`` on ',' to create
      a list of ``checksums``

  - This list of key/value is the ``qualifiers`` object

- Split the ``remainder`` once from left on ':'

  - The left side lowercased is the ``scheme``
  - The right side is the ``remainder``

- Strip all leading and trailing '/' characters (e.g., '/', '//', '///' and
  so on) from the ``remainder``

  - Split this once from left on '/'
  - The left side lowercased is the ``type``
  - The right side is the ``remainder``

- Split the ``remainder`` once from right on '@'

  - The left side is the ``remainder``
  - Percent-decode the right side. This is the ``version``.
  - UTF-8-decode the ``version`` if needed in your programming language
  - This is the ``version``

- Split the ``remainder`` once from right on '/'

  - The left side is the ``remainder``
  - Percent-decode the right side. This is the ``name``
  - UTF-8-decode this ``name`` if needed in your programming language
  - Apply type-specific normalization to the ``name`` if needed
  - This is the ``name``

- Split the ``remainder`` on '/'

  - Discard any empty segment from that split
  - Percent-decode each segment
  - UTF-8-decode each segment if needed in your programming language
  - Apply type-specific normalization to each segment if needed
  - Join segments back with a '/'
  - This is the ``namespace``


Known ``purl`` types
~~~~~~~~~~~~~~~~~~~~

There are several known ``purl`` package type definitions tracked in the
separate `<PURL-TYPES.rst>`_ document.

Known ``qualifiers`` key/value pairs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note: Do not abuse ``qualifiers``: it can be tempting to use many qualifier
keys but their usage should be limited to the bare minimum for proper package
identification to ensure that a ``purl`` stays compact and readable in most cases.

Additional, separate external attributes stored outside of a ``purl`` are the
preferred mechanism to convey extra long and optional information such as a
download URL, VCS URL or checksums in an API, database or web form.


With this warning, the known ``key`` and ``value`` defined here are valid for use in
all package types:

- ``repository_url`` is an extra URL for an alternative, non-default package
  repository or registry. When a package does not come from the default public
  package repository for its ``type`` a ``purl`` may be qualified with this extra
  URL. The default repository or registry of a ``type`` is documented in the
  "Known ``purl`` types" section.

- ``download_url`` is an extra URL for a direct package web download URL to
  optionally qualify a ``purl``.

- ``vcs_url`` is an extra URL for a package version control system URL to
  optionally qualify a ``purl``. The syntax for this URL should be as defined in
  Python pip or the SPDX specification. See
  https://github.com/spdx/spdx-spec/blob/cfa1b9d08903/chapters/3-package-information.md#37-package-download-location

  - TODO: incorporate the details from SPDX here.

- ``file_name`` is an extra file name of a package archive.

- ``checksum`` is a qualifier for one or more checksums stored as a
  comma-separated list. Each item in the ``value`` is in form of
  ``lowercase_algorithm:hex_encoded_lowercase_value`` such as
  ``sha1:ad9503c3e994a4f611a4892f2e67ac82df727086``.
  For example (with checksums truncated for brevity) ::

       checksum=sha1:ad9503c3e994a4f,sha256:41bf9088b3a1e6c1ef1d


Tests
~~~~~

To support the language-neutral testing of ``purl`` implementations, a test suite
is provided as JSON document named ``test-suite-data.json``. This JSON document
contains an array of objects. Each object represents a test with these key/value
pairs some of which may not be normalized:

- **purl**: a ``purl`` string.
- **canonical**: the same ``purl`` string in canonical, normalized form
- **type**: the ``type`` corresponding to this ``purl``.
- **namespace**: the ``namespace`` corresponding to this ``purl``.
- **name**: the ``name`` corresponding to this ``purl``.
- **version**: the ``version`` corresponding to this ``purl``.
- **qualifiers**: the ``qualifiers`` corresponding to this ``purl`` as an object of
  {key: value} qualifier pairs.
- **subpath**: the ``subpath`` corresponding to this ``purl``.
- **is_invalid**: a boolean flag set to true if the test should report an
  error

To test ``purl`` parsing and building, a tool can use this test suite and for
every listed test object, run these tests:

- parsing the test canonical ``purl`` then re-building a ``purl`` from these parsed
  components should return the test canonical ``purl``

- parsing the test ``purl`` should return the components parsed from the test
  canonical ``purl``

- parsing the test ``purl`` then re-building a ``purl`` from these parsed components
  should return the test canonical ``purl``

- building a ``purl`` from the test components should return the test canonical ``purl``


Package URL Type definitions
============================

Each package manager, platform, type, or ecosystem has its own conventions and
protocols to identify, locate, and provision software packages.

The package **type** is the component of a package URL that is used to capture
this information with a short string such as ``maven``, ``npm``, ``nuget``, ``gem``,
``pypi``, etc.


These are known ``purl`` package type definitions.

Known ``purl`` type definitions are formalized here independent of the core
Package URL specification. See also a candidate list further down.

Definitions can also include types reserved for future use.

See also https://github.com/package-url/purl-spec and
`<PURL-SPECIFICATION.rst>`_ for the Package URL specification.


Known ``purl`` types
~~~~~~~~~~~~~~~~~~~~

alpm
----
``alpm`` for Arch Linux and other users of the libalpm/pacman package manager.

- There is no default package repository: this should be implied either from
  the ``distro`` qualifiers key  or using a repository base url as
  ``repository_url`` qualifiers key.
- The ``namespace`` is the vendor such as ``arch``, ``arch32``, ``archarm``,
  ``manjaro`` or ``msys``. It is not case sensitive and must be lowercased.
- The ``name`` is the package name. It is not case sensitive and must be lowercased.
- The ``version`` is the version of the package as specified in [`vercmp(8)`](https://man.archlinux.org/man/vercmp.8#DESCRIPTION) as part of alpm.
- The ``arch`` is the qualifiers key for a package architecture.
- Examples::

      pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64
      pkg:alpm/arch/python-pip@21.0-1?arch=any
      pkg:alpm/arch/containers-common@1:0.47.4-4?arch=x86_64

apk
---
``apk`` for APK-based packages:

- There is no default package repository: this should be implied either from
  the ``distro`` qualifiers key  or using a repository base url as
  ``repository_url`` qualifiers key.
- The ``namespace`` is the vendor such as ``alpine`` or ``openwrt``. It is not
  case sensitive and must be lowercased.
- The ``name`` is the package name. It is not case sensitive and must be
  lowercased.
- The ``version`` is a package version as expected by apk.
- The ``arch`` is the qualifiers key for a package architecture.
- Examples::

      pkg:apk/alpine/curl@7.83.0-r0?arch=x86
      pkg:apk/alpine/apk@2.12.9-r3?arch=x86

bitbucket
---------
``bitbucket`` for Bitbucket-based packages:

- The default repository is ``https://bitbucket.org``.
- The ``namespace`` is the user or organization. It is not case sensitive and
  must be lowercased.
- The ``name`` is the repository name. It is not case sensitive and must be
  lowercased.
- The ``version`` is a commit or tag.
- Examples::

      pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c

bitnami
-------
``bitnami`` for Bitnami-based packages:

- The default repository is ``https://downloads.bitnami.com/files/stacksmith``.
- The ``name`` is the component name. It must be lowercased.
- The ``version`` is the full Bitnami package version, including version and revision.
- The ``arch`` is the qualifiers key for a package architecture. Available values: ``amd64`` (default) and ``arm64``.
- The ``distro`` is the qualifiers key for the distribution associated to the package.
- Examples::

      pkg:bitnami/wordpress?distro=debian-12
      pkg:bitnami/wordpress@6.2.0?distro=debian-12
      pkg:bitnami/wordpress@6.2.0?arch=arm64&distro=debian-12
      pkg:bitnami/wordpress@6.2.0?arch=arm64&distro=photon-4

cocoapods
---------
``cocoapods`` for CocoaPods:

- The default repository is ``https://cdn.cocoapods.org/``.
- The ``name`` is the pod name and is case sensitive, cannot contain whitespace, a plus (`+`) character, or begin with a period (`.`).
- The ``version`` is the package version.
- The purl subpath is used to represent a pods subspec (if present).
- Examples::

      pkg:cocoapods/AFNetworking@4.0.1
      pkg:cocoapods/MapsIndoors@3.24.0
      pkg:cocoapods/ShareKit@2.0#Twitter
      pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib

cargo
-----
``cargo`` for Rust:

- The default repository is ``https://crates.io/``.
- The ``name`` is the repository name.
- The ``version`` is the package version.
- Examples::

      pkg:cargo/rand@0.7.2
      pkg:cargo/clap@2.33.0
      pkg:cargo/structopt@0.3.11

composer
--------
``composer`` for Composer PHP packages:

- The default repository is ``https://packagist.org``.
- The ``namespace`` is the vendor.
- The ``namespace`` and ``name`` are not case sensitive and must be lowercased.
- Note: private, local packages may have no name. In this case you cannot
  create a ``purl`` for these.
- Examples::

      pkg:composer/laravel/laravel@5.5.0

conan
-----
``conan`` for Conan C/C++ packages. The purl is designed to closely resemble the Conan-native `<package-name>/<package-version>@<user>/<channel>` `syntax for package references <https://docs.conan.io/en/1.46/cheatsheet.html#package-terminology>`_.

- ``name``: The Conan ``<package-name>``.
- ``version``: The Conan ``<package-version>``.
- ``namespace``: The vendor of the package.
- Qualifier ``user``: The Conan ``<user>``. Only required if the Conan package was published with ``<user>``.
- Qualifier ``channel``: The Conan ``<channel>``. Only required if the Conan package was published with Conan ``<channel>``.
- Qualifier ``rrev``: The Conan recipe revision (optional). If omitted, the purl refers to the latest recipe revision available for the given version.
- Qualifier ``prev``: The Conan package revision (optional). If omitted, the purl refers to the latest package revision available for the given version and recipe revision.
- Qualifier ``repository_url``: The Conan repository where the package is available (optional). If omitted, ``https://center.conan.io`` as default repository is assumed.

Additional qualifiers can be used to distinguish Conan packages with different settings or options, e.g. ``os=Linux``, ``build_type=Debug`` or ``shared=True``.

If no additional qualifiers are used to distinguish Conan packages build with different settings or options, then the purl is ambiguous and it is up to the user to work out which package is being referred to (e.g. with context information).

Examples::

      pkg:conan/openssl@3.0.3
      pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
      pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c

conda
-----
``conda`` for Conda packages:

- The default repository is ``https://repo.anaconda.com``.
- The ``name`` is the package name.
- The ``version`` is the package version.
- The qualifiers: ``build`` is the build string.
  ``channel`` is the package stored location.
  ``subdir`` is the associated platform.
  ``type`` is the package type.
- Examples::

      pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2

cpan
----
``cpan`` for CPAN Perl packages:

- The default repository is ``https://www.cpan.org/``.
- The ``namespace``:
  - To refer to a CPAN distribution name, the ``namespace`` MUST be present. In this case, the namespace is the CPAN id of the author/publisher. It MUST be written uppercase, followed by the distribution name in the ``name`` component. A distribution name MUST NOT contain the string ``::``.
  - To refer to a CPAN module, the ``namespace`` MUST be absent. The module name MAY contain zero or more ``::`` strings, and the module name MUST NOT contain a ``-``

- The ``name`` is the module or distribution name and is case sensitive.
- The ``version`` is the module or distribution version.
- Optional qualifiers may include:

  - ``repository_url``: CPAN/MetaCPAN/BackPAN/DarkPAN repository base URL (default is ``https://www.cpan.org``)
  - ``download_url``: URL of package or distribution
  - ``vcs_url``: extra URL for a package version control system
  - ``ext``: file extension (default is ``tar.gz``)

- Examples::

      pkg:cpan/Perl::Version@1.013
      pkg:cpan/DROLSKY/DateTime@1.55
      pkg:cpan/DateTime@1.55
      pkg:cpan/GDT/URI-PackageURL
      pkg:cpan/LWP::UserAgent
      pkg:cpan/OALDERS/libwww-perl@6.76
      pkg:cpan/URI

cran
-----
``cran`` for CRAN R packages:

- The default repository is ``https://cran.r-project.org``.
- The ``name`` is the package name and is case sensitive, but there cannot be two packages on CRAN with the same name ignoring case.
- The ``version`` is the package version.
- Examples::

      pkg:cran/A3@1.0.0
      pkg:cran/rJava@1.0-4
      pkg:cran/caret@6.0-88

deb
---
``deb`` for Debian, Debian derivatives, and Ubuntu packages:

- There is no default package repository: this should be implied either from
  the ``distro`` qualifiers key or using a base url as a ``repository_url``
  qualifiers key.
- The ``namespace`` is the "vendor" name such as "debian" or "ubuntu".
  It is not case sensitive and must be lowercased.
- The ``name`` is not case sensitive and must be lowercased.
- The ``version`` is the version of the binary (or source) package.
- ``arch`` is the qualifiers key for a package architecture. The special value
  ``arch=source`` identifies a Debian source package that usually consists of a
  Debian Source control file (.dsc) and corresponding upstream and Debian
  sources. The ``dpkg-query`` command can print the ``name`` and ``version`` of
  the corresponding source package of a binary package::

    dpkg-query -f '${source:Package} ${source:Version}' -W <binary package name>

- Examples::

      pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
      pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
      pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
      pkg:deb/debian/attr@1:2.4.47-2?arch=source
      pkg:deb/debian/attr@1:2.4.47-2%2Bb1?arch=amd64

docker
------
``docker`` for Docker images:

- The default repository is ``https://hub.docker.com``.
- The ``namespace`` is the registry/user/organization if present.
- The version should be the image id sha256 or a tag. Since tags can be moved,
  a sha256 image id is preferred.
- Examples::

      pkg:docker/cassandra@latest
      pkg:docker/smartentry/debian@dc437cc87d10
      pkg:docker/customer/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io

gem
---
``gem`` for RubyGems:

- The default repository is ``https://rubygems.org``.
- The ``platform`` qualifiers key is used to specify an alternative platform.
  such as ``java`` for JRuby. The implied default is ``ruby`` for Ruby MRI.
- Examples::

      pkg:gem/ruby-advisory-db-check@0.12.4
      pkg:gem/jruby-launcher@1.1.2?platform=java

generic
-------
``generic`` for plain, generic packages that do not fit anywhere else such as
for "upstream-from-distro" packages. In particular this is handy for a plain
version control repository such as a bare git repo.

- There is no default repository. A ``download_url`` and ``checksum`` may be
  provided in `qualifiers` or as separate attributes outside of a ``purl`` for
  proper identification and location.
- When possible another or a new purl ``type`` should be used instead of using
  the ``generic`` type and eventually contributed back to this specification.
- as for other ``type``, the ``name`` component is mandatory. In the worst case
  it can be a file or directory name.
- Examples (truncated for brevity)::

      pkg:generic/openssl@1.1.10g
      pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
      pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32


github
------
``github`` for GitHub-based packages:

- The default repository is ``https://github.com``.
- The ``namespace`` is the user or organization. It is not case sensitive and
  must be lowercased.
- The ``name`` is the repository name. It is not case sensitive and must be
  lowercased.
- The ``version`` is a commit or tag.
- Examples::

      pkg:github/package-url/purl-spec@244fd47e07d1004
      pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs

golang
------
``golang`` for Go packages:

- There is no default package repository: this is implied in the namespace
  using the ``go get`` command conventions.
- The ``namespace`` and `name` must be lowercased.
- The ``subpath`` is used to point to a subpath inside a package.
- The ``version`` is often empty when a commit is not specified and should be
  the commit in most cases when available.
- Examples::

      pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c
      pkg:golang/google.golang.org/genproto#googleapis/api/annotations
      pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api

hackage
-------
``hackage`` for Haskell packages:

- The default repository is `https://hackage.haskell.org`.
- The `version` is package version.
- The `name` is case sensitive and use kebab-case.
- Examples::

      pkg:hackage/a50@0.5
      pkg:hackage/AC-HalfInteger@1.2.1
      pkg:hackage/3d-graphics-examples@0.0.0.2

hex
---
``hex`` for Hex packages:

- The default repository is ``https://repo.hex.pm``.
- The ``namespace`` is optional; it may be used to specify the organization for
  private packages on hex.pm. It is not case sensitive and must be lowercased.
- The ``name`` is not case sensitive and must be lowercased.
- Examples::

      pkg:hex/jason@1.1.2
      pkg:hex/acme/foo@2.3.
      pkg:hex/phoenix_html@2.13.3#priv/static/phoenix_html.js
      pkg:hex/bar@1.2.3?repository_url=https://myrepo.example.com


huggingface
------
``huggingface`` for Hugging Face ML models

- The default repository is ``https://huggingface.co``.
- The ``namespace`` is the model repository username or organization, if present. It is case sensitive.
- The ``name`` is the model repository name. It is case sensitive.
- The ``version`` is the model revision Git commit hash. It is case insensitive and must be lowercased in the package URL.
- Examples::

      pkg:huggingface/distilbert-base-uncased@043235d6088ecd3dd5fb5ca3592b6913fd516027
      pkg:huggingface/microsoft/deberta-v3-base@559062ad13d311b87b2c455e67dcd5f1c8f65111?repository_url=https://hub-ci.huggingface.co


luarocks
--------
``luarocks`` for Lua packages installed with LuaRocks:

- ``namespace``: The user manifest under which the package is registered.
  If not given, the root manifest is assumed.
  It is case insensitive, but lowercase is encouraged since namespaces
  are normalized to ASCII lowercase.
- ``name``: The LuaRocks package name.
  It is case insensitive, but lowercase is encouraged since package names
  are normalized to ASCII lowercase.
- ``version``: The full LuaRocks package version, including module version
  and rockspec revision.
  It is case sensitive, and lowercase must be used to avoid
  compatibility issues with older LuaRocks versions.
  The full version number is required to uniquely identify a version.
- Qualifier ``repository_url``: The LuaRocks rocks server to be used;
  useful in case a private server is used (optional).
  If omitted, ``https://luarocks.org`` as default server is assumed.

Examples::

      pkg:luarocks/luasocket@3.1.0-1
      pkg:luarocks/hisham/luafilesystem@1.8.0-1
      pkg:luarocks/username/packagename@0.1.0-1?repository_url=https://example.com/private_rocks_server/


maven
-----
``maven`` for Maven JARs and related artifacts:

- The default ``repository_url`` is ``https://repo.maven.apache.org/maven2``.
- The group id is the ``namespace`` and the artifact id is the ``name``.
- Known qualifiers keys are: ``classifier`` and ``type`` as defined in the
  POM documentation. Note that Maven uses a concept / coordinate called packaging
  which does not map directly 1:1 to a file extension. In this use case, we need
  to construct a link to one of many possible artifacts. Maven itself uses type
  in a dependency declaration when needed to disambiguate between them.
- Examples::

      pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1
      pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom
      pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=sources
      pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist
      pkg:maven/net.sf.jacob-projec/jacob@1.14.3?classifier=x86&type=dll
      pkg:maven/net.sf.jacob-projec/jacob@1.14.3?classifier=x64&type=dll
      pkg:maven/groovy/groovy@1.0?repository_url=https://maven.google.com


mlflow
------
``mlflow`` for MLflow ML models (Azure ML, Databricks, etc.)

- The repository is the MLflow tracking URI. There is no default. Examples:

  - Azure ML: ``https://<region>.api.azureml.ms/mlflow/v1.0/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.MachineLearningServices/workspaces/<workspace-name>``
  - Azure Databricks: ``https://adb-<numbers>.<number>.azuredatabricks.net/api/2.0/mlflow``
  - AWS Databricks: ``https://dbc-<alphanumeric>-<alphanumeric>.cloud.databricks.com/api/2.0/mlflow``
  - GCP Databricks: ``https://<numbers>.<number>.gcp.databricks.com/api/2.0/mlflow``

- The ``namespace`` is empty.
- The ``name`` is the model name. Case sensitivity depends on the server implementation:

  - Azure ML: it is case sensitive and must be kept as-is in the package URL.
  - Databricks: it is case insensitive and must be lowercased in the package URL.

- The ``version`` is the model version.
- Known qualifiers keys are: ``model_uuid`` and ``run_id`` as defined in the MLflow documentation.
- Examples::

      pkg:mlflow/creditfraud@3?repository_url=https://westus2.api.azureml.ms/mlflow/v1.0/subscriptions/a50f2011-fab8-4164-af23-c62881ef8c95/resourceGroups/TestResourceGroup/providers/Microsoft.MachineLearningServices/workspaces/TestWorkspace
      pkg:mlflow/trafficsigns@10?model_uuid=36233173b22f4c89b451f1228d700d49&run_id=410a3121-2709-4f88-98dd-dba0ef056b0a&repository_url=https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow


npm
---
``npm`` for Node NPM packages:

- The default repository is ``https://registry.npmjs.org``.
- The ``namespace`` is used for the scope of a scoped NPM package.
- Per the package.json spec, new package "must not have uppercase letters in
  the name", therefore the must be lowercased.
- Examples::

      pkg:npm/foobar@12.3.1
      pkg:npm/%40angular/animation@12.3.1
      pkg:npm/mypackage@12.4.5?vcs_url=git://host.com/path/to/repo.git%404345abcd34343

nuget
-----
``nuget`` for NuGet .NET packages:

- The default repository is ``https://www.nuget.org``.
- There is no ``namespace`` per se even if the common convention is to use
  dot-separated package names where the first segment is ``namespace``-like.
- Examples::

      pkg:nuget/EnterpriseLibrary.Common@6.0.1304

qpkg
----
``qpkg`` for QNX packages:

- There is no default package repository: this should be implied either from
  the ``namespace`` or using a repository base URL as ``repository_url``
  qualifiers key.
- The ``namespace`` is the vendor of the package. It is not case sensitive and must be
  lowercased.
- Examples::

      pkg:qpkg/blackberry/com.qnx.sdp@7.0.0.SGA201702151847
      pkg:qpkg/blackberry/com.qnx.qnx710.foo.bar.qux@0.0.4.01449T202205040833L

oci
------------
``oci`` for all artifacts stored in registries that conform to the
`OCI Distribution Specification <https://github.com/opencontainers/distribution-spec>`_,
including container images built by Docker and others:

- There is no canonical package repository for OCI artifacts. Therefore
  ``oci`` purls must be registry agnostic by default. To specify the repository,
  provide a ``repository_url`` value.
- OCI purls do not contain a ``namespace``, although, ``repository_url`` may
  contain a namespace as part of the physical location of the package.
- The ``name`` is not case sensitive and must be lowercased. The name is the
  last fragment of the repository name. For example if the repository
  name is ``library/debian`` then the ``name`` is ``debian``.
- The ``version`` is the ``sha256:hex_encoded_lowercase_digest`` of the
  artifact and is required to uniquely identify the artifact.
- Optional qualifiers may include:

  - ``arch``: key for a package architecture, when relevant.
  - ``repository_url``: A repository URL where the artifact may be found, but not
    intended as the only location. This value is encouraged to identify a
    location the content may be fetched.
  - ``tag``: artifact tag that may have been associated with the digest at the time.
- Examples::

      pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=docker.io/library/debian&arch=amd64&tag=latest
      pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
      pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
      pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1

pub
----
``pub`` for Dart and Flutter packages:

- The default repository is ``https://pub.dartlang.org``.
- Pub normalizes all package names to be lowercase and using underscores. The only allowed characters are `[a-z0-9_]`.
- More information on pub naming and versioning is available in the [pubspec documentation](https://dart.dev/tools/pub/pubspec)
- Examples::

      pkg:pub/characters@1.2.0
      pkg:pub/flutter@0.0.0

pypi
----
``pypi`` for Python packages:

- The default repository is ``https://pypi.org``. (Previously  ``https://pypi.python.org``.)
- PyPI treats ``-`` and ``_`` as the same character and is not case sensitive.
  Therefore a PyPI package ``name`` must be lowercased and underscore ``_``
  replaced with a dash ``-``.
- The ``file_name`` qualifier selects a particular distribution file
  (case-sensitive). For naming convention, see the Python Packaging User Guide on
  `source distributions <https://packaging.python.org/en/latest/specifications/source-distribution-format/#source-distribution-file-name>`_,
  `binary distributions <https://packaging.python.org/en/latest/specifications/binary-distribution-format/#file-name-convention>`_,
  and `platform compatibility tags <https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/>`_.
- Examples::

      pkg:pypi/django@1.11.1
      pkg:pypi/django@1.11.1?filename=Django-1.11.1.tar.gz
      pkg:pypi/django@1.11.1?filename=Django-1.11.1-py2.py3-none-any.whl
      pkg:pypi/django-allauth@12.23

rpm
---
``rpm`` for RPMs:

- There is no default package repository: this should be implied either from
  the ``distro`` qualifiers key or using a repository base URL as
  ``repository_url`` qualifiers key.
- The ``namespace`` is the vendor such as Fedora or OpenSUSE.
  It is not case sensitive and must be lowercased.
- The ``name`` is the RPM name and is case sensitive.
- The ``version`` is the combined version and release of an RPM.
- ``epoch`` (optional for RPMs) is a qualifier as it's not required for
  unique identification, but when the epoch exists we strongly
  encourage using it.
- ``arch`` is the qualifiers key for a package architecture.
- Examples::

      pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25
      pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25

swid
-----
``swid`` for ISO-IEC 19770-2 Software Identification (SWID) tags:

- There is no default package repository.
- The ``namespace`` is the optional name and regid of the entity with a role of softwareCreator. If specified, name is required and is the first segment in the namespace. If regid is known, it must be specified as the second segment in the namespace. A maximum of two segments are supported.
- The ``name`` is the name as defined in the SWID SoftwareIdentity element.
- The ``version`` is the version as defined in the SWID SoftwareIdentity element.
- The qualifier ``tag_id`` must not be empty and corresponds to the tagId as defined in the SWID SoftwareIdentity element. Per the SWID specification, GUIDs are recommended. If a GUID is used, it must be lowercase. If a GUID is not used, the tag_id qualifier is case aware but not case sensitive.
- The qualifier ``tag_version`` is an optional integer and corresponds to the tagVersion as defined in the SWID SoftwareIdentity element. If not specified, defaults to 0.
- The qualifier ``patch`` is optional and corresponds to the patch as defined in the SWID SoftwareIdentity element. If not specified, defaults to false.
- The qualifier ``tag_creator_name`` is optional. If the tag creator is different from the software creator, the tag_creator_name qualifier should be specified.
- The qualifier ``tag_creator_regid`` is optional. If the tag creator is different from the software creator, the tag_creator_regid qualifier should be specified.

Use of known qualifiers key/value pairs such as ``download_url`` can be used to specify where the package was retrieved from.

- Examples::

      pkg:swid/Acme/example.com/Enterprise+Server@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d
      pkg:swid/Fedora@29?tag_id=org.fedoraproject.Fedora-29
      pkg:swid/Adobe+Systems+Incorporated/Adobe+InDesign@CC?tag_id=CreativeCloud-CS6-Win-GM-MUL

swift
-----
``swift`` for Swift packages:

- There is no default package repository: this should be implied from ``namespace``.
- The ``namespace`` is source host and user/organization and is required.
- The ``name`` is the repository name.
- The ``version`` is the package version and is required.
- Examples::

      pkg:swift/github.com/Alamofire/Alamofire@5.4.3
      pkg:swift/github.com/RxSwiftCommunity/RxFlow@2.12.4

Other candidate types to define:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``apache`` for Apache projects packages:
- ``android`` for Android apk packages:
- ``atom`` for Atom packages:
- ``bower`` for Bower JavaScript packages:
- ``brew`` for Homebrew packages:
- ``buildroot`` for Buildroot packages
- ``carthage`` for Cocoapods Cocoa packages:
- ``chef`` for Chef packages:
- ``chocolatey`` for Chocolatey packages
- ``clojars`` for Clojure packages:
- ``coreos`` for CoreOS packages:
- ``ctan`` for CTAN TeX packages:
- ``crystal`` for Crystal Shards packages:
- ``drupal`` for Drupal packages:
- ``dtype`` for DefinitelyTyped TypeScript type definitions:
- ``dub`` for D packages:
- ``elm`` for Elm packages:
- ``eclipse`` for Eclipse projects packages:
- ``gitea`` for Gitea-based packages:
- ``gitlab`` for GitLab-based packages:
- ``gradle`` for Gradle plugins
- ``guix`` for Guix packages:
- ``haxe`` for Haxe packages:
- ``helm`` for Kubernetes packages
- ``julia`` for Julia packages:
- ``melpa`` for Emacs packages
- ``meteor`` for Meteor JavaScript packages:
- ``nim`` for Nim packages:
- ``nix`` for Nixos packages:
- ``opam`` for OCaml packages:
- ``openwrt`` for OpenWRT packages:
- ``osgi`` for OSGi bundle packages:
- ``p2`` for Eclipse p2 packages:
- ``pear`` for Pear PHP packages:
- ``pecl`` for PECL PHP packages:
- ``perl6`` for Perl 6 module packages:
- ``platformio`` for PlatformIO packages:
- ``ebuild`` for Gentoo Linux portage packages:
- ``puppet`` for Puppet Forge packages:
- ``sourceforge`` for Sourceforge-based packages:
- ``sublime`` for Sublime packages:
- ``terraform`` for Terraform modules
- ``vagrant`` for Vagrant boxes
- ``vim`` for Vim scripts packages:
- ``wordpress`` for Wordpress packages:
- ``yocto`` for Yocto recipe packages:



======================================================
vers: a mostly universal version range specifier
======================================================

This specification is a new syntax for dependency and vulnerable version ranges.


Context
--------

Software package version ranges and version constraints are essential:

- When resolving the dependencies of a package to express which subset of the
  versions are supported. For instance a dependency or requirement statement
  such as "I require package foo, version 2.0 or later versions" defines a
  range of acceptable foo versions.

- When stating that a known vulnerability or bug affects a range of package
  versions. For instance a security advisory such as "vulnerability 123 affects
  package bar, version 3.1 and version 4.2 but not version 5" defines a range of
  vulnerable "bar" package versions.

Version ranges can be replaced by a list enumerating all the versions of
interest. But in practice, all the versions may not yet exist when defining an
open version range such as "v2.0 or later".

Therefore, a version range is a necessary, compact and practical way to
reference multiple versions rather than listing all the versions.


Problem
--------

Several version range notations exist and have evolved separately to serve the
specific needs of each package ecosystem, vulnerability databases and tools.

There is no (mostly) universal notation for version ranges and there is no
universal way to compare two versions, even though the concepts that exist in
most version range notations are similar.

Each package type or ecosystem may define their own ranges notation and version
comparison semantics for dependencies. And for security advisories, the lack of
a portable and compact notation for vulnerable package version ranges means that
these ranges may be either ambiguous or hard to compute and may be best replaced
by complete enumerations of all impacted versions, such as in the `NVD CPE Match
feed <https://nvd.nist.gov/vuln/data-feeds#cpeMatch>`_.

Because of this, expressing and resolving a version range is often a complex, or
error prone task.

In particular the need for common notation for version has emerged based on the
usage of Package URLs referencing vulnerable package version ranges such as in
vulnerability databases like `VulnerableCode
<https://github.com/nexB/vulnerablecode/>`_.

To better understand the problem, here are some of the many notations and
conventions in use:

- ``semver`` https://semver.org/ is a popular specification to structure version
  strings, but does not provide a way to express version ranges.

- RubyGems strongly suggest using ``semver`` for version but does not enforce it.
  As a result some gem use semver while several popular package do not use
  strict semver. RubyGems use their own notation for version ranges which
  looks like the ``node-semver`` notation with some subtle differences.
  See https://guides.rubygems.org/patterns/#semantic-versioning

- ``node-semver`` ranges are used in npm at https://github.com/npm/node-semver#ranges
  with range semantics that are specific to ``semver`` versions and npm.

- Dart pub versioning scheme is similar to ``node-semver`` and the documentation
  at https://dart.dev/tools/pub/versioning provides a comprehensive coverage of
  the topic of versioning. Version resolution uses its own algorithm.

- Python uses its own version and version ranges notation with notable
  peculiarities on how pre-release and post-release suffixes are used
  https://www.python.org/dev/peps/pep-0440/

- Debian and Ubuntu use their own notation and are remarkable for their use of
  ``epochs`` to disambiguate versions.
  https://www.debian.org/doc/debian-policy/ch-relationships.html

- RPM distros use their own range notation and use epochs like Debian.
  https://rpm-software-management.github.io/rpm/manual/dependencies.html

- Perl CPAN defines its own version range notation similar to this specification
  and uses two-segment versions. https://metacpan.org/pod/CPAN::Meta::Spec#Version-Ranges

- Apache Maven and NuGet use similar math intervals notation using brackets
  https://en.wikipedia.org/wiki/Interval_(mathematics)

  - Apache Maven http://maven.apache.org/enforcer/enforcer-rules/versionRanges.html
  - NuGet https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges

- gradle uses Apache Maven notation with some extensions
  https://docs.gradle.org/current/userguide/single_versions.html

- Gentoo and Alpine Linux use comparison operators similar to this specification:
  - Gentoo https://wiki.gentoo.org/wiki/Version_specifier
  - Alpine linux https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c

- Arch Linux https://wiki.archlinux.org/title/PKGBUILD#Dependencies use its
  own simplified notation for its PKGBUILD depends array and use a modified
  RPM version comparison.

- Go modules https://golang.org/ref/mod#versions use ``semver`` versions with
  specific version resolution algorithms.

- Haskell Package Versioning Policy https://pvp.haskell.org/ provides a notation
  similar to this specification based on a modified semver with extra notations
  such as star and caret.

- The NVD https://nvd.nist.gov/vuln/data-feeds#cpeMatch defines CPE ranges as
  lists of version start and end either including or excluding the start or end
  version. And also provides a concrete enumeration of the available ranges as
  a daily feed.

- The version 5 of the CVE JSON data format at
  https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0.schema#L303
  defines version ranges with a starting version, a versionType, and an upper
  limit for the version range as lessThan or lessThanOrEqual; or an enumeration
  of versions. The versionType is defined as ``"The version numbering system
  used for specifying the range. This defines the exact semantics of the
  comparison (less-than) operation on versions, which is required to understand
  the range itself"``. A "versionType" resembles closely the Package URL package
  "type".

- The OSSF OSV schema https://ossf.github.io/osv-schema/ defines vulnerable
  ranges with version events using "introduced", "fixed" and "limit" fields and
  an optional enumeration of all the versions in these ranges, except for
  semver-based versions. A range may be ecosystem-specific based on a provided
  package "ecosystem" value that resembles closely the Package URL package
  "type".


The way two versions are compared as equal, lesser or greater is a closely
related topic:

- Each package ecosystem may have evolved its own peculiar version string
  conventions, semantics and comparison procedure.

- For instance, ``semver`` is a prominent specification in this domain but this
  is just one of the many ways to structure a version string.

- Debian, RPM, PyPI, RubyGems, and Composer have their own subtly different
  approach on how to determine how two versions are compared as equal, greater
  or lesser.


Solution
---------

A solution to the many version range syntaxes is to design a new simplified
notation to unify them all with:

- a mostly universal and minimalist, compact notation to express version ranges
  from many different package types and ecosystems.

- the package type-specific definitions to normalize existing range expressions
  in this common notation.

- the designation of which algorithm or procedure to use when comparing two
  versions such that it is possible to resolve if a version is within or
  outside of a version range.

We call this solution "version range specifier" or "vers" and it is described
in this document.


Version range specifier
------------------------

A version range specifier (aka. "vers") is a URI string using the ``vers``
URI-scheme with this syntax::

   vers:<versioning-scheme>/<version-constraint>|<version-constraint>|...

For example, to define a set of versions that contains either version ``1.2.3``,
or any versions greater than or equal to ``2.0.0`` but less than ``5.0.0`` using
the ``node-semver`` versioning scheme used with the ``npm`` Package URL type,
the version range specifier will be::

    vers:npm/1.2.3|>=2.0.0|<5.0.0

``vers`` is the URI-scheme and is an acronym for "VErsion Range Specifier". It
has been selected because it is short, obviously about version and available
for a future formal URI-scheme registration at IANA.

The pipe "|" is used as a simple separator between ``<version-constraint>``.
Each ``<version-constraint>`` in this pipe-separated list contains a comparator
and a version::

    <comparator:version>

This list of ``<version-constraint>`` are signposts in the version timeline of
a package that specify version intervals.

A ``<version>`` satisfies a version range specifier if it is contained within
any of the intervals defined by these ``<version-constraint>``.


Using version range specifiers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``vers`` primary usage is to test if a version is within a range.

An version is within a version range if falls in any of the intervals defined
by a range. Otherwise, the version is outside of the version range.

Some important usages derived from this include:

- **Resolving a version range specifier to a list of concrete versions.**
  In this case, the input is one or more known versions of a package. Each
  version is then tested to check if it lies within or outside the range. For
  example, given a vulnerability and the ``vers`` describing the vulnerable
  versions of a package, this process is used to determine if an existing
  package version is vulnerable.

- **Selecting one of several versions that are within a range.**
  In this case, given several versions that are within a range and several
  packages that express package dependencies qualified by a version range,
  a package management tools will determine and select the set of package
  versions that satisfy all the version ranges constraints of all dependencies.
  This usually requires deploying heuristics and algorithms (possibly complex
  such as sat solvers) that are ecosystem- and tool-specific and outside of the
  scope for this specification; yet ``vers`` could be used in tandem with
  ``purl`` to provide an input to this dependencies resolution process.


Examples
~~~~~~~~~

A single version in an npm package dependency:

- originally seen as a dependency on version "1.2.3" in a package.json manifest
- the version range spec is: ``vers:npm/1.2.3``


A list of versions, enumerated:

- ``vers:pypi/0.0.0|0.0.1|0.0.2|0.0.3|1.0|2.0pre1``


A complex statement about a vulnerability in a "maven" package that affects
multiple branches each with their own fixed versions at
https://repo1.maven.org/maven2/org/apache/tomee/apache-tomee/
Note how the constraints are sorted:


- "affects Apache TomEE 8.0.0-M1 - 8.0.1, Apache TomEE 7.1.0 - 7.1.2,
  Apache TomEE 7.0.0-M1 - 7.0.7, Apache TomEE 1.0.0-beta1 - 1.7.5."

- a normalized version range spec is:
  ``vers:maven/>=1.0.0-beta1|<=1.7.5|>=7.0.0-M1|<=7.0.7|>=7.1.0|<=7.1.2|>=8.0.0-M1|<=8.0.1``

- alternatively, four ``vers`` express the same range, using one ``vers`` for
  each vulnerable "branches":
  - ``vers:tomee/>=1.0.0-beta1|<=1.7.5``
  - ``vers:tomee/>=7.0.0-M1|<=7.0.7``
  - ``vers:tomee/>=7.1.0|<=7.1.2``
  - ``vers:tomee/>=8.0.0-M1|<=8.0.1``

Conversing RubyGems custom syntax for dependency on gem. Note how the
pessimistic version constraint is expanded:

- ``'library', '~> 2.2.0', '!= 2.2.1'``
- the version range spec is: ``vers:gem/>=2.2.0|!= 2.2.1|<2.3.0``


URI scheme
~~~~~~~~~~

The ``vers`` URI scheme is  an acronym for "VErsion Range Specifier".
It has been selected because it is short, obviously about version and available
for a future formal registration for this URI-scheme at the IANA registry.

The URI scheme is followed by a colon ":".


``<versioning-scheme>``
~~~~~~~~~~~~~~~~~~~~~~~

The ``<versioning-scheme>`` (such as ``npm``, ``deb``, etc.) determines:

- the specific notation and conventions used for a version string encoded in
  this scheme. Versioning schemes often specify a version segments separator and
  the meaning of each version segments, such as [major.minor.patch] in semver.

- how two versions are compared as greater or lesser to determine if a version
  is within or outside a range.

- how a versioning scheme-specific range notation can be transformed in the
  ``vers`` simplified notation defined here.

By convention the versioning scheme **should** be the same as the ``Package URL``
package type for a given package ecosystem. It is OK to have other schemes
beyond the purl type. A scheme could be specific to a single package name.

The ``<versioning-scheme>`` is followed by a slash "/".


``<version-constraint>``
~~~~~~~~~~~~~~~~~~~~~~~~

After the ``<versioning-scheme>`` and "/" there are one or more
``<version-constraint>`` separated by a pipe "|". The pipe "|" has no special
meaning beside being a separator.

Each  ``<version-constraint>`` of this list is either a single ``<version>`` as
in ``1.2.3`` for example or the combination of a ``<comparator>`` and a ``<version>`` as in
``>=2.0.0`` using this syntax::

    <comparator><version>

A single version that means that a version equal to this version satisfies the
range spec. Equality is based on the equality of two normalized version strings
according to their versioning scheme. For most schemes, this is a simple string
equality. But schemes can specify normalization and rules for equality such as
``pypi`` with PEP440.


The special star "*" comparator matches any version. It must be used **alone**
exclusive of any other constraint and must not be followed by a version. For
example "vers:deb/\*" represent all the versions of a Debian package. This
includes past, current and possible future versions.


Otherwise, the ``<comparator>`` is one of these comparison operators:

- "!=": Version exclusion or inequality comparator. This means a version must
  not be equal to the provided version that must be excluded from the range.
  For example: "!=1.2.3" means that version "1.2.3" is excluded.

- "<", "<=": Lesser than or lesser-or-equal version comparators point to all
  versions less than or equal to the provided version.
  For example "<=1.2.3" means less than or equal to "1.2.3".

- ">", ">=": Greater than or greater-or-equal version comparators point to
  all versions greater than or equal to the provided version.
  For example ">=1.2.3" means greater than or equal to "1.2.3".


The ``<versioning-scheme>`` defines:

- how to compare two version strings using these comparators, and

- the structure of a version string such as "1.2.3" if any. For instance, the
  ``semver`` specification for version numbers  defines a version as composed
  primarily of three dot-separated numeric segments named major, minor and patch.



Normalized, canonical representation and validation
-----------------------------------------------------

The construction and validation rules are designed such that a ``vers`` is
easier to read and understand by human and straight forward to process by tools,
attempting to avoid the creation of empty or impossible version ranges.

- Spaces are not significant and removed in a canonical form. For example
  "<1.2.3|>=2.0" and " <  1.2. 3 | > = 2  . 0" are equivalent.

- A version range specifier contains only printable ASCII letters, digits and
  punctuation.

- The URI scheme and versioning scheme are always lowercase as in ``vers:npm``.

- The versions are case-sensitive, and a versioning scheme may specify its own
  case sensitivity.

- If a ``version`` in a ``<version-constraint>`` contains separator or
  comparator characters (i.e. ``><=!*|``), it must be quoted using the URL
  quoting rules. This should be rare in practice.

The list of ``<version-constraint>s`` of a range are signposts in the version
timeline of a package. With these few and simple validation rules, we can avoid
the creation of most empty or impossible version ranges:

- **Constraints are sorted by version**. The canonical ordering is the versions
  order. The ordering of ``<version-constraint>`` is not significant otherwise
  but this sort order is needed when check if a version is contained in a range.

- **Versions are unique**. Each ``version`` must be unique in a range and can
  occur only once in any ``<version-constraint>`` of a range specifier,
  irrespective of its comparators. Tools must report an error for duplicated
  versions.

- **There is only one star**: "*" must only occur once and alone in a range,
  without any other constraint or version.

Starting from a de-duplicated and sorted list of constraints, these extra rules
apply to the comparators of any two contiguous constraints to be valid:

- "!=" constraint can be followed by a constraint using any comparator, i.e.,
  any of "=", "!=", ">", ">=", "<", "<=" as comparator (or no constraint).

Ignoring all constraints with "!=" comparators:

- A "=" constraint must be followed only by a constraint with one of "=", ">",
  ">=" as comparator (or no constraint).

And ignoring all constraints with "=" or "!=" comparators, the sequence of
constraint comparators must be an alternation of greater and lesser comparators:

- "<" and "<=" must be followed by one of ">", ">=" (or no constraint).
- ">" and ">=" must be followed by one of "<", "<=" (or no constraint).

Tools must report an error for such invalid ranges.


Parsing and validating version range specifiers
-------------------------------------------------

To parse a version range specifier string:

- Remove all spaces and tabs.
- Start from left, and split once on colon ":".
- The left hand side is the URI-scheme that must be lowercase.
  - Tools must validate that the URI-scheme value is ``vers``.
- The right hand side is the specifier.

- Split the specifier from left once on a slash "/".

- The left hand side is the <versioning-scheme> that must be lowercase.
  Tools should validate that the <versioning-scheme> is a known scheme.

- The right hand side is a list of one or more constraints.
  Tools must validate that this constraints string is not empty ignoring spaces.

- If the constraints string is equal to "*", the ``<version-constraint>`` is "*".
  Parsing is done and no further processing is needed for this ``vers``. A tool
  should report an error if there are extra characters beyond "*".

- Strip leading and trailing pipes "|" from the constraints string.
- Split the constraints on pipe "|". The result is a list of ``<version-constraint>``.
  Consecutive pipes must be treated as one and leading and trailing pipes ignored.

- For each ``<version-constraint>``:
  - Determine if the ``<version-constraint>`` starts with one of the two comparators:

    - If it starts with ">=", then the comparator is ">=".
    - If it starts with "<=", then the comparator is "<=".
    - If it starts with "!=", then the comparator is "!=".
    - If it starts with "<",  then the comparator is "<".
    - If it starts with ">",  then the comparator is ">".

    - Remove the comparator from ``<version-constraint>`` string start. The
      remaining string is the version.

  - Otherwise the version is the full ``<version-constraint>`` string (which implies
    an equality comparator of "=")

  - Tools should validate and report an error if the version is empty.

  - If the version contains a percent "%" character, apply URL quoting rules
    to unquote this string.

  - Append the parsed (comparator, version) to the constraints list.

Finally:

- The results are the ``<versioning-scheme>`` and the list of ``<comparator, version>``
  constraints.

Tools should optionally validate and simplify the list of ``<comparator, version>``
constraints once parsing is complete:

- Sort and validate the list of constraints.
- Simplify the list of constraints.


Version constraints simplification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tools can simplify a list of ``<version-constraint>`` using this approach:

These pairs of contiguous constraints with these comparators are valid:

- != followed by anything
- =, <, or <= followed by =, !=, >, or >=
- >, or >= followed by !=, <, or <=

These pairs of contiguous constraints with these comparators are redundant and
invalid (ignoring any != since they can show up anywhere):

- =, < or <= followed by < or <=: this is the same as < or <=
- > or >= followed by =, > or >=: this is the same as > or >=


A procedure to remove redundant constraints can be:

- Start from a list of constraints of comparator and version, sorted by version
  and where each version occurs only once in any constraint.

- If the constraints list contains a single constraint (star, equal or anything)
  return this list and simplification is finished.

- Split the constraints list in two sub lists:

  - a list of "unequal constraints" where the comparator is "!="
  - a remainder list of "constraints" where the comparator is not "!="

- If the remainder list of "constraints" is empty, return the "unequal constraints"
  list and simplification is finished.

- Iterate over the constraints list, considering the current and next contiguous
  constraints, and the previous constraint (e.g., before current) if it exists:

    - If current comparator is ">" or ">=" and next comparator is "=", ">" or ">=",
      discard next constraint

    - If current comparator is "=", "<" or "<="  and next comparator is <" or <=",
      discard current constraint. Previous constraint becomes current if it exists.

    - If there is a previous constraint:

        - If previous comparator is ">" or ">=" and current comparator is "=", ">" or ">=",
          discard current constraint

        - If previous comparator is "=", "<" or "<=" and current comparator is <" or <=",
          discard previous constraint

- Concatenate the "unequal constraints" list and the filtered "constraints" list
- Sort by version and return.


Checking if a version is contained within a range
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To check if a "tested version" is contained within a version range:

- Start from a parsed a version range specifier with:

  - a versioning scheme
  - a list of constraints of comparator and version, sorted by version
    and where each version occurs only once in any constraint.

- If the constraint list contains only one item and the comparator is "*",
  then the "tested version" is IN the range. Check is finished.

- Select the version equality and comparison procedures suitable for this
  versioning scheme and use these for all version comparisons performed below.

- If the "tested version" is equal to the any of the constraint version
  where the constraint comparator is for equality (any of "=", "<=", or ">=")
  then the "tested version" is in the range. Check is finished.

- If the "tested version" is equal to the any of the constraint version where
  the constraint comparator is "=!" then the "tested version" is NOT in the
  range. Check is finished.

- Split the constraint list in two sub lists:

  - a first list where the comparator is "=" or "!="
  - a second list where the comparator is neither "=" nor "!="

- Iterate over the current and next contiguous constraints pairs (aka. pairwise)
  in the second list.

- For each current and next constraint:

    - If this is the first iteration and current comparator is "<" or <="
      and the "tested version" is less than the current version
      then the "tested version" is IN the range. Check is finished.

    - If this is the last iteration and next comparator is ">" or >="
      and the "tested version" is greater than the next version
      then the "tested version" is IN the range. Check is finished.

    - If current comparator is ">" or >=" and next comparator is "<" or <="
      and the "tested version" is greater than the current version
      and the "tested version" is less than the next version
      then the "tested version" is IN the range. Check is finished.

    - If current comparator is "<" or <=" and next comparator is ">" or >="
      then these versions are out the range. Continue to the next iteration.

- Reaching here without having finished the check before means that the
  "tested version" is NOT in the range.


Notes and caveats
~~~~~~~~~~~~~~~~~~~

- Comparing versions from two different versioning schemes is an error. Even
  though there may be some similarities between the ``semver`` version of an npm
  and the ``deb`` version of its Debian packaging, the way versions are compared
  specific to each versioning scheme and may be different. Tools should report
  an error in this case.

- All references to sorting or ordering of version constraints means sorting
  by version. And sorting by versions always implies using the versioning
  scheme-specified version comparison and ordering.


Some of the known versioning schemes
----------------------------------------

These are a few known versioning schemes for some common Package URL
`types` (aka. ``ecosystem``).

- **deb**: Debian and Ubuntu https://www.debian.org/doc/debian-policy/ch-relationships.html
  Debian uses these comparators: <<, <=, =, >= and >>.

- **rpm**: RPM distros https://rpm-software-management.github.io/rpm/manual/dependencies.html
  The a simplified rmpvercmp version comparison routine is used by Arch Linux Pacman.

- **gem**: RubyGems https://guides.rubygems.org/patterns/#semantic-versioning
  which is similar to ``node-semver`` for its syntax, but does not use semver
  versions.

- **npm**: npm uses node-semver which is based on semver with its own range
  notation https://github.com/npm/node-semver#ranges
  A similar but different scheme is used by Rust
  https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html
  and several other package types may use ``node-semver``-like ranges. But most
  of these related schemes are not strictly the same as what is implemented in
  ``node-semver``. For instance PHP ``composer`` may need its own scheme as this
  is not strictly ``node-semver``.

- **composer**: PHP https://getcomposer.org/doc/articles/versions.md

- **pypi**: Python https://www.python.org/dev/peps/pep-0440/

- **cpan**: Perl https://perlmaven.com/how-to-compare-version-numbers-in-perl-and-for-cpan-modules

- **golang**: Go modules https://golang.org/ref/mod#versions use ``semver`` versions
  with a specific minimum version resolution algorithm.

- **maven**: Apache Maven supports a math interval notation which is rarely seen
  in practice http://maven.apache.org/enforcer/enforcer-rules/versionRanges.html

- **nuget**: NuGet https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges
  Note that Apache Maven and NuGet are following a similar approach with a
  math-derived intervals syntax as in https://en.wikipedia.org/wiki/Interval_(mathematics)

- **gentoo**: Gentoo https://wiki.gentoo.org/wiki/Version_specifier

- **alpine**: Alpine linux https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c
  which is using Gentoo-like conventions.

- **generic**: a generic version comparison algorithm (which will be specified
  later, likely based on a split on any wholly alpha or wholly numeric segments
  and dealing with digit and string comparisons, like is done in libversion)


TODO: add Rust, composer and archlinux, nginx, tomcat, apache.

A separate document will provide details for each versioning scheme and:

- how to convert its native range notation to the ``vers`` notation and back.
- how to compare and sort two versions in a range.

This versioning schemes document will also explain how to convert CVE and OSV
ranges to ``vers``.


Implementations
-----------------------

- Python: https://github.com/nexB/univers
- Java: https://github.com/nscuro/versatile
- Yours!



Related efforts and alternative
------------------------------------

- CUDF defines a generic range notation similar to Debian and integer version
  numbers from the sequence of versions for universal dependencies resolution
  https://www.mancoosi.org/cudf/primer/

- OSV is an "Open source vulnerability DB and triage service." It defines
  vulnerable version range semantics using a minimal set of comparators for use
  with package "ecosystem" and version range "type".
  https://github.com/google/osv

- libversion is a library for general purpose version comparison using a
  unified procedure designed to work with many package types.
  https://github.com/repology/libversion

- unified-range is a library for uniform version ranges based on the Maven
  version range spec. It support Apache Maven and npm ranges
  https://github.com/snyk/unified-range

- dephell specifier is a library to parse and evaluate version ranges and
  "work with version specifiers (can parse PEP-440, SemVer, Ruby, NPM, Maven)"
  https://github.com/dephell/dephell_specifier


Why not reuse existing version range notations?
-----------------------------------------------------

Most existing version range notations are tied to a specific version string
syntax and are therefore not readily applicable to other contexts. For example,
the use of elements such as tilde and caret ranges in RubyGems, npm or Dart
notations implies that a certain structure exists in the version string (semver
or semver- like). The inclusion of these additional comparators is a result of
the history and evolution in a given package ecosystem to address specific needs.

In practice, the unified and reduced set of comparators and syntax defined for
``vers`` has been designed such that all these notations can be converted to a
``vers`` and back from a ``vers`` to the original notation.

In contrast, this would not be possible with existing notations. For instance,
the Python notation may not work with npm semver versions and reciprocally.

There are likely to be a few rare cases where round tripping from and to
``vers`` may not be possible, and in any case round tripping to and from ``vers``
should produce equivalent results and even if not strictly the same original
strings.

Another issue with existing version range notations is that they are primarily
designed for dependencies and not for vulnerable ranges. In particular, a
vulnerability may exist for multiple "version branches" of a given package such
as with Django 2.x and 3.x. Several version range notations have difficulties to
communicate these as typically all the version constraints must be satisfied.
In contrast,  a vulnerability can affect multiple disjoint version ranges of a
package and any version satisfying these constraints would be vulnerable: it
may not be possible to express this with a notation designed exclusively for
dependent versions resolution.

Finally, one of the goals of this spec is to be a compact yet obvious Package
URL companion for version ranges. Several existing and closely related notations
designed for vulnerable ranges are verbose specifications designed for use
in API with larger JSON documents.


Why not use the OSV Ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://ossf.github.io/osv-schema/

``vers`` and the OSSF OSV schema vulnerable ranges are equivalent and ``vers``
provides a compact range notation while OSV provides more verbose JSON notation.

``vers`` borrows the design from and was informed by the OSV schema spec and its
authors.

OSV uses a minimalist set of only three comparators:

- "=" to enumerate versions,
- ">=" for the version that introduced a vulnerability, and
- "<"  for the version that fixed a vulnerability.

OSV Ranges support neither ">" nor "!=" comparators making it difficult to
express some ranges that must exclude a version. This may not be an issue for
most vulnerable ranges yet:

- this makes it difficult or impossible to precisely express certain dependency
  and vulnerable ranges when a version must be excluded and the set of existing
  versions is not yet known,

- this make some ranges more verbose such as with the CVE v5 API ranges
  notation that can include their upper limit and would need two constraints.

Another high level difference between the two specifications are the
codes used to qualify a range package  "ecosystem" value that resembles closely
the Package URL package "type" used in ``vers``. This spec will provide a strict
mapping between the OSV ecosystem and the ``vers`` versioning schemes values.


Why not use the CVE v5 API Ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json#L303
- https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json#L123

The version 5 of the CVE JSON data format defines version ranges with a
starting version, a versionType, and an upper limit for the version range as
lessThan or lessThanOrEqual or as an enumeration of versions. The versionType
and the package collectionURL possible values are only indicative and left out
of this specification and both seem strictly equivalent to the Package URL
"type" on the one hand and the ``vers`` versioning scheme on the other hand.

The semantics and expressiveness of each range are similar and ``vers`` provides
a compact notation rather than a more verbose JSON notation. ``vers`` supports
strictly the conversion of any CVE v5 range to its notation and further
provides a concrete list of well known versioning schemes. ``vers`` design was
informed by the CVE v5 API schema spec and its authors.

When CVE v5 becomes active, this spec will provide a strict mapping between the
CVE ``versionType`` and the ``vers`` versioning schemes values. Furthermore, this
spec and the Package URL "types" should be updated accordingly to provide
a mapping with the upcoming CVE ``collectionURL`` that will be effectively used.

There is one issue with CVE v5: it introduces a new trailing "*" notation that
does not exists in most version ranges notations and may not be computable
easily in many cases. The description of the "lessThan" property is:

    The non-inclusive upper limit of the range. This is the least version NOT
    in the range. The usual version syntax is expanded to allow a pattern to end
    in an asterisk `(*)`, indicating an arbitrarily large number in the version
    ordering. For example, `{version: 1.0 lessThan: 1.*}` would describe the
    entire 1.X branch for most range kinds, and `{version: 2.0, lessThan: *}`
    describes all versions starting at 2.0, including 3.0, 5.1, and so on.

The conversion to ``vers`` range should be:

- with a version 1.0 and `"lessThan": "*"`, the ``vers`` equivalent is: ``>=1.0``.

- with a version 1.0 and `"lessThan": "2.*"`, the ``vers`` equivalent can be
  computed for ``semver`` versions as ``>=1.0|<2`` but is not accurate unless
  as versioning schemes have different rules. For instance, pre-release may be
  treated in some case as part of the v1. branch and in some other cases as part
  of the v2. branch. It is not clear if with "2.*"  the CVE v5 spec means:

    - ``<2``
    - or something that excludes any version string that starts with ``2.``

And in this case, with the expression `"lessThan": "2.*"` using  a ``semver``
version, it is not clear if ``2.0.0-alpha`` is "lessThan"; semver sorts it
before ``2.0`` and after ``1.0``, e.g., in ``semver`` ``2.0.0-alpha`` is
"less than" ``2``.


Why not use the NVD CPE Ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://nvd.nist.gov/vuln/vulnerability-detail-pages#divRange
- https://nvd.nist.gov/developers/vulnerabilities#divResponse
- https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema

The version ranges notation defined in the JSON schema of the CVE API payload
uses these four fields: ``versionStartIncluding``, ``versionStartExcluding``,
``versionEndIncluding`` and ``versionEndExcluding``. For example::

    "versionStartIncluding": "7.3.0",
    "versionEndExcluding": "7.3.31",
    "versionStartExcluding" : "9.0.0",
    "versionEndIncluding" : "9.0.46",

In addition to these ranges, the NVD publishes a list of concrete CPE with
versions resolved for a range with daily updates at
https://nvd.nist.gov/vuln/data-feeds#cpeMatch

Note that the NVD CVE configuration is a complex specification that goes well
beyond version ranges and is used to match comprehensive configurations across
multiple products and version ranges. ``vers`` focus is exclusively versions.

In contrast with ``vers`` compact notation, the NVD JSON notation is more
verbose, yet ``vers`` supports strictly the conversion of any CPE range.


Why not use node-semver ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://github.com/npm/node-semver#ranges

The node-semver spec is similar but much more complex than this spec. This is
an AND of ORs constraints with a few practical issues:

- A space means "AND", therefore white spaces are significant. Having
  significant white spaces in a string makes normalization more complicated and
  may be a source of confusion if you remove the spaces from the string.
  ``vers`` avoids the ambiguity of spaces by ignoring them.

- The advanced range syntax has grown to be rather complex using hyphen ranges,
  stars ranges, carets and tilde constructs that are all tied to the JavaScript
  and npm ways of handling versions in their ecosystem and are bound furthermore
  to the semver semantics and its npm implementation. These are not readily
  reusable elsewhere. The multiple comparators and modifiers make the notation
  grammar more complex to parse and process for a machine and harder to read for
  human.

Notations that are directly derived from node-semver as used in Rust and PHP
Composer have the same issues.


Why not use Python PEP-0440 ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://www.python.org/dev/peps/pep-0440/#version-specifiers

The Python pep-0440 "Version Identification and Dependency Specification"
provides a comprehensive specification for Python package versioning and a
notation for "version specifiers" to express the version constraints of
dependencies.

This specification is similar to this ``vers`` spec, with more operators and
aspects specific to the versions used only in the Python ecosystem.

- In particular pep-0440 uses tilde, triple equal and wildcard star operators
  that are specific to how two Python versions are compared.

- The comma separator between constraints is a logical "AND" rather than an
  "OR". The "OR" does not exist in the syntax making some version ranges
  harder to express, in particular for vulnerabilities that may affect several
  exact versions or ranges for multiple parallel release branches. Ranges such as
  "Django 1.2 or later, or Django 2.2 or later or Django 3.2 or later" are
  difficult to express without an "OR" logic.


Why not use RubyGems requirements notation?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See:

- https://guides.rubygems.org/patterns/#declaring-dependencies

The RubyGems specification suggests but does not enforce using semver. It uses
operators similar to the ``node-semver`` spec with the different of the "~>"
aka. pessimistic operator vs. a plain "~" tilde used in node-semver.  This
operator implies some semver-like versioning, yet gem version are not strictly
semver. This makes the notation complex to implement and impractical to reuse
in places that do not use the same Ruby-specific semver-like semantics.


Why not use fewer comparators with only =, >= and <?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For instance, the OSV schema adopts a reduced set of only three comparators:

- "=" is implied when used to enumerate vulnerable versions
- ">=" (greater or equal) is for the version that introduces a vulnerability
- "<" (lesser) is for the version that fixes a vulnerability

This approach is simpler and works well for most vulnerable ranges but it faces
limitations when converting from other notations:

- ">" cannot be converted reliably to ">=" unless you know all the versions and
  these will never change.

- "<=" cannot be converted reliably to "<" unless you know all the versions and
  these will never change.

- "!=" cannot be converted reliably: there is no ">" comparator to create an
  unequal equivalent of "><"; and a combo of ">=" and "<" is not equivalent
  to inequality unless you know all the versions and these will never change.


Why not use richer comparators such as tilde, caret and star?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some existing notations such as used with npm, gem, python, or composer
provide syntactic shorthand such as:

- a "pessimistic operator" using tilde, ~> or =~  as in "~1.3" or "~>1.2.3"
- a caret ^ prefix as in "^ 1.2"
- using a star in a version segment as in "1.2.*"
- dash-separated ranges as in "1.2 - 1.4"
- arbitrary string equality such as "===1.2"

Most of these notations can be converted without loss to the ``vers`` notation.
Furthermore these notations typically assume a well defined version string
structure specific to their package ecosystem and are not reusable in another
ecosystem that would not use the exact same version conventions.

For instance, the tilde and caret notations demand that you can reliably
infer the next version (aka. "bump") from a given version; this is possible
only if the versioning scheme supports this operation reliably for all its
accepted versions.


Why not use mathematical interval notation for ranges?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apache Maven and NuGet use a mathematical interval notation with comma-separated
"[", "]", "(" and ")"  to declare version ranges.

All other known range notations use the more common ">", "<", and "=" as
comparators. ``vers`` adopts this familiar approach.