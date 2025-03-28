Google Summer of Code 2021 Final Report
============================================

Organization - `AboutCode <https://www.aboutcode.org>`_
-----------------------------------------------------------
| `Hritik Vijay <https://github.com/hritik14>`_
| Project: `VulnerableCode <https://github.com/aboutcode-org/vulnerablecode>`_

Overview
---------
VulnerableCode is a decentralized python program to collect data about open
source software vulnerabilities across the internet.  My proposal for this
year's Google Summer of Code involved improving the import speed, refactoring
existing code, finding points for overall improvement and adding importers.

Detailed Report
-----------------

Improve Import Time
^^^^^^^^^^^^^^^^^^^^
Profiling showed that a lot of time was being wasted during auto commits
undertaken by django. Wraping the importer in an atomic block avoids lots of
database commits and shows huge performance improvement. This simple change
allows for much faster import times while not drastically changing the code
structure::

    Alpine: 202.7s -> 50.9s
    Archlinux 2116.6s -> 107.8s
    Gentoo 3176.3s -> 225.8s

Yielding an average of 93% reduction in time (14x faster)

More: https://github.com/aboutcode-org/vulnerablecode/pull/478

Speed up upstream tests
^^^^^^^^^^^^^^^^^^^^^^^^
VulnerableCode performs upstream tests for all the importers to make sure that
any change change in upstream data structure is easily spotted. This allows us
to have a look at failing importers without actually deploying the application.

Earlier, all of the importers were run one by one in order to verify that they
are intact. While this being the obvious and the full proof way to detect any
anomalies in the imported data schema, it did not work because the time
required to run all the importers much exceeded 6 hours - which is the maximum
time allowed for GitHub actions to run.
With this PR, the updated_advisories method of each importer is expected to
create at least one Advisory object. If it does so, the importer is marked
working. While this is not full proof, it stays much below the allowed resource
usage cap. In the end, this is a trade off between resource usage and data
accuracy.  This brings major performance improvement during the test.

| Before: ~6hrs, now ~9 minutes
| More: https://github.com/aboutcode-org/vulnerablecode/pull/490

Improve Docker Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The preferred mode of deployment for VulnerableCode is deploying using Docker
images. Docker configuration existing earlier was very insecure and
rudimentary. I took the inspiration for a uniform Docker configuration from the
ScanCodeIO project and provided with detailed documentation for installation
using a docker image. The current configuration makes use of files like
``docker.env`` to supply container's environment and ``.dockerignore`` to skip
over any unnecessary files for deployment.

| More:
| https://github.com/aboutcode-org/vulnerablecode/pull/497
| https://github.com/aboutcode-org/vulnerablecode/pull/521

Add Makefile
^^^^^^^^^^^^^
Makefile usage is prevalent in sister projects like `ScanCodeIO
<https://github.com/nexB/scancode.io>`_. It gives VulnerableCode a consistent
behavior and provides a very friendly interface for invocations. This also
avoids security risks like having a default django ``SECRET_KEY`` as it can be
easily generated by a make target.  I added a Makefile which has a similar
usage as that of ScanCodeIO, replaced all the CI tests to use make, updated the
relevant part of the documentation and updated settings to reject insecure
deployments.

| More:
| https://github.com/aboutcode-org/vulnerablecode/pull/497
| https://github.com/aboutcode-org/vulnerablecode/pull/523

Use svn to collects tags in GitHubTagsAPI
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Surprisingly, GitHub allows svn requests to repositories. Now we can
have all the tags with a single request. This is much more efficient and
gentle to the APIs.
This was as issue since the importers based on GithubDataSource were `failing
<https://github.com/aboutcode-org/vulnerablecode/issues/507>`_ because of being rate
limited by GitHub.

| `Philippe <https://github.com/pombredanne>`_, thank you so much for the suggestion
| More: https://github.com/aboutcode-org/vulnerablecode/pull/508

Separate import and improve operations - WIP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
This introduces a new concept of ``improver``. Earlier, data fetching and
improvement were done as one single process by ``importer``. This meant that
importers were convoluted and not very modular. The concept of ``improver``
comes from the idea that an ``importer`` should only do one thing - import. Any
further improvement on the data is delegated to the improvers. This allows for
us to have multiple ways of improvement with certain confidence on the improved
data making the import and improve operations modular and simpler to work with.
As a bonus, writing importers will be very easy and welcome more contributors
to the project. As of writing this report, this remains a work in progress
which will be finished very soon.

More: https://github.com/aboutcode-org/vulnerablecode/pull/525

Others
^^^^^^^
- helper: split_markdown_front_matter: https://github.com/aboutcode-org/vulnerablecode/pull/443
- Dump yaml in favor of saneyaml https://github.com/aboutcode-org/vulnerablecode/pull/452
- Refactor package_managers https://github.com/aboutcode-org/vulnerablecode/pull/495/commits
- Importers bugfix https://github.com/aboutcode-org/vulnerablecode/pull/505

Pre GSoC
----------

I started to like VulnerableCode as soon as I laid eyes on the project. While
exploring the codebase, I realized that there is a lot of room for improvement.
Thus I looked for simple improvements and bugs to fix in the early stage, which
were:

- `Correct API docs path and fix pytest invocation <https://github.com/aboutcode-org/vulnerablecode/pull/379>`_
- `Explicity provide lxml parser to beautifulsoup <https://github.com/aboutcode-org/vulnerablecode/pull/382>`_
- `Make sure vulnerability id is_cve or is_vulcoid <https://github.com/aboutcode-org/vulnerablecode/pull/389>`_
- `Fix istio importer <https://github.com/aboutcode-org/vulnerablecode/pull/395>`_ (cleared a huge confusion about the codebase)
- `Add me to AUTHORS <https://github.com/aboutcode-org/vulnerablecode/pull/405>`_ (Should've done this a lot earlier)
- `Add unspecified scoring system <https://github.com/aboutcode-org/vulnerablecode/pull/415>`_
- `Fix redhat import failure <https://github.com/aboutcode-org/vulnerablecode/pull/418>`_ (This one took a *lot* of effort to pinpoint)
- `expose find_all_cve helper <https://github.com/aboutcode-org/vulnerablecode/pull/439>`_

Post GSoC - Future Plans and what's left
-------------------------------------------
I wish to carry on with the development of VulnerableCode and implement the
ideas suggested by my mentors. This will require a lot of effort to bring
VulnerableCode to a stable point. I hope to see VulnerableCode integrated into
the ScanCode toolkit happen in a near future.

Further, if possible, I would like VulnerableCode to interact with other great
open source tools like *Eclipse Steady* and *Prospector*.  VulnerableCode,
currently, works statically to collect all the vulnerabilities from different
data sources, meanwhile there have been some developments with the Prospector
project of Eclipse Steady. The project aims to scan fix-commits of the git
repository in order to find out if the vulnerable part of a library was
actually used in a project. It is not always the case that if a library is
vulnerable then all the projects building upon it would be vulnerable too. It
is crucial to identify if it is worth updating the library in use and dealing
with the breaking changes.  *Prospectus* is undergoing improvements in order to
be released as a usable public tool. *Project KB* (Under Eclipse Steady) is
also working on a "tool support for mining repositories and databases of
advisories to establish the (missing) link between vulnerabilities (as
described in natural language in the advisories) and the corresponding
fix-commits".  When these projects are ready for public use I would like to add
them to VulnerableCode as a modules. I hope this will benefit both the projects
and the downstream.

After everything mentioned above, writing importers and improvers is something
that is still left. In my opinion, this needs to be addressed after having a
stable structure for VulnerableCode.

Closing Thoughts
-------------------
I really enjoyed working on the project. There were ups and downs when I met
some weird bugs but every one of them taught me something new about Python,
Django and programming in general. The best part of working with my amazing
mentors - Philippe and Shivam - were the `weekly meets
<https://github.com/aboutcode-org/vulnerablecode/wiki/WeeklyMeetings#meeting-on-tuesday-2021-08-17-at-1400-utc>`_
where we would together try to figure out how to proceed with the development.
I learned something new with every call and interaction we had. Thank you so
much my mentors for providing a very smooth experience and Google for showing
me the guiding light for participation.

To the reader, I would really like you to read `this <https://en.wikipedia.org/wiki/Program_optimization#When_to_optimize>`_
before Philippe asks you to ;)
