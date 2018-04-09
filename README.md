# sr-dynamic-rerouting

## Installation

Use **Vagrant** to run a virtual environment with all the dependencies with `vagrant up`.

Then run `make` to compile the project.

## Emulate a network

Running `python test/run.py <network-name>` will launch a Mininet emulation of the software on the network given as argument.

Other options can be seen by running `python -h test/run.py`

## Running automated tests

Running `python test/run.py -a <network-name>` will trigger all the automated tests.

