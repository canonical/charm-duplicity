# Overview
This is a template for writing charms with unit and functional testing included
from the start. It is meant to provide a quick start to creating a charm and
encourage testing from the beginning.

The template comes out of the box with a build script that will build the charm.
There are empty folders for interfaces, layers, and the charm source. Interfaces
and Layers are pulled from upstream but this template recommends adding subrepos
in the appropriate folder to the charm to allow tracking of versions for
interfaces and layers. If an interface or layers is present in the folder it
will be used instead of the upstream.

To build simply run the Makefile target
```bash
make build
```

Testing is done via tox and there are two environments setup, one for unit and
one for functional testing. Each has a separate requirements file to setup the
virtualenv that they will be run in. These requirements are only needed for
running the tests.

Unit testing is performed via pytest. Tests are defined in
/tests/unit/test_XXX.py

To run unit test with tox run:
```bash
make unittest
```

Out of the gate, unit testing just verifies that the testing framework is
working. It is recommend that the library file in the lib folder be fully unit
tested.


The currently supported method of functional testing uses libjuju to interact
with juju and the units.

To run libjuju functional testing:
```bash
make functional
```
This requires a controller; a temporary model will be created and torn down at
the beginning and end of the testing session, respectively. A custom
module-scoped event loop is provided as to support fixtures with scopes beyond
'function'.

Several generic fixtures are provided in conftest.py, and reuse is encouraged.
