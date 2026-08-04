.. _reference_framework_overview:

Framework Overview
--------------------

.. code-block::

                                                             ┌────────────┐
       ┌──────────────────────┐                              │            │                                          ┌─────────────────────┐
       │                      │                              │  Database  │ Has version ranges                       │                     │
       │                      ├─────────────────────────────►│    in      │                                          │                     │
       │                      │                              │  Advisory  │ As true as upstream                      │                     │
       │                      │                              │    Model   │                                          │                     │
       │                      │                              │            │                                          │   Frontend          │
       │                      │                              ├────────────┘                                          │                     │
       │      Importers       │                              │                                                       │                     │
       │                      │                              │                                                       │                     │
       │                      │                              │                                                       │                     │
       │                      │                              │                                                       │                     │
       │                      │                              │                                                       │                     │
       │                      │                              │                                                       │                     │
       └──────────────────────┘                              │                               ┌──────────────────────►│                     │
                                                             │                               │                       └─────────────────────┘
                                                             │                               │
                                                             │                               │
                                                             │                               │
                                                             │                               │
         ┌──────────────────────────────────┐                │                               │
         │                                  │                │                               │
         │                                  │◄───────────────┘                         ┌──────────────────────┐
         │                                  │                                          │ Package              │
         │                                  │                                          │                      │
         │    Specific                      │                                          ├──────────────────────┤
         │    Improvers                     │                                          │  purl                │
         │                                  │                                          │  Package URL         │
         │ - GroupAdvisoriesForPackages     ├─────────────────────────────────────────►├──────────────────────┤
         │ - FlagGhostPackagePipeline       │                                          │  Aff by advisories   │
         │ - MarkUnfurlVersionRangePipeline │                                          │                      │
         │ - ComputePackageRiskPipeline     │                                          ├──────────────────────┤
         │ - ...                            │                                          │                      │
         │                                  │                                          │  Fixed by advisories │
         └──────────────────────────────────┘                                          ├──────────────────────┤
                                                                                       │    ...               │
                                                                                       └──────────────────────┘
                                                                                                ▲
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                                                                                │
                                              Independent to access any Advisory                │
             ┌─────────────────────────┐        Generic to all data                             │
             │                         │                                                        │
             │                         │ ───────────────────────────────────────────────────────┘
             │   Generic Improvers     │
             │                         │
             │     - DefaultImprover   │
             │     - ...               │
             │                         │
             │                         │
             │                         │
             │                         │
             └─────────────────────────┘



