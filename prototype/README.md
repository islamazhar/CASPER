## CASPER Prototype Implementation

This is a basic prototype implementation of CASPER using the  using the [py_webauthn](https://github.com/duo-labs/py_webauthn) library.

## Requirements

- Python 3.9+

## Starting the demo

First, set up a virtual environment:

```sh
python3 -m venv casper_env && source venv/bin/activate
```

Next, install dependencies:

```sh
pip install -r requirements.txt
```

Finally, run the server to view the demo at http://localhost:5000:

```sh
./start-server.sh
```