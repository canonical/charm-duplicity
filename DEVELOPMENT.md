# Duplicity - Development

This is a quick guide to help developers start contributing to the Duplicity charm project.

## Getting Started

This section will help with setting up the development and testing environment for this charm.

### Prerequisites

What you'll need is:

- charm-tools
- tox
- python3
- juju

To download:

```
sudo snap install charm --classic
sudo snap install juju --classic

pip install tox
```

### Dev Setup

Here's some quick commands to help you get started developing:

```
# Clone the repo
git clone git+ssh://git.launchpad.net/charm-duplicity

# Get virtual environment. Then you can set this as your project interpreter (helpful with PyCharm)
tox -e func-noop
source .tox/func-noop/bin/activate
```

### Building the charm

You can build the charm through different methods:

```
# Build using make command
make build

# Build using charm tools command
charm build
```

## Running Tests

The following section will review running automated tests in the project.

### Unit Tests

Unit tests utilize the [pytest framework](https://docs.pytest.org/en/latest/).

TODO: Unit tests still need to be implemented fully. However, running them is simple. You can use the make 
command or call pytest directly:

```
make unittest

# or

pytest

``` 

### Functional Tests

This project uses [zaza](https://zaza.readthedocs.io/en/latest/addingcharmtests.html) for it's functional
test framework. This provides a solid structure for testing as well as the `functest` tool for granular
control over the functional test lifecycle.

**Note**: the bundles zaza uses grab the local charm from the default `/tmp/charm-builds/duplicity`
directory. You can change this in the bundle, however please refrain from pushing said change as this will
move away from the default.

You can run the full test suite using make (will also build the charm before running):

```
make functional

# use tox to skip the build step
tox -e functional
```

You can also use `functest` to run the suite in chunks, separating the preparation, deployment, configuration, and
allowing singular test class to be run. You can find more information regarding these functions in the zaza docs
[here](https://zaza.readthedocs.io/en/latest/runningcharmtests.html).

### Code Style lint

This project uses various linting techniques and tools. To run against the code run the following:

```
make lint
```

## Authors

[Llama (LMA) Charmers](https://launchpad.net/~llama-charmers)
