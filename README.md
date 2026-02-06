# bqConnect CLI

[![PyPI - Version](https://img.shields.io/pypi/v/openbq)](https://pypi.python.org/pypi/openbq)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/openbq)](https://pypi.python.org/pypi/openbq)
[![PyPI - Format](https://img.shields.io/pypi/format/openbq)](https://pypi.python.org/pypi/openbq)
[![PyPI - License](https://img.shields.io/pypi/l/openbq)](https://pypi.python.org/pypi/openbq)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/openbq)](https://pypi.python.org/pypi/openbq)

> bqconnect CLI (`openbq`) is part of the openbq framework. openbq is an open-source tool designed to empower biometric quality assessment, for more details please visit: [openbq](https://openbq.io).

> bqconnect CLI provides a command line interface to access biometric data quality evaluations for various modalities, including [face](https://docs.openbq.io/modalities/face.html), [fingerprint](https://docs.openbq.io/modalities/fingerprint.html), [iris](https://docs.openbq.io/modalities/iris.html), and [voice](https://docs.openbq.io/modalities/voice.html).

## Highlights

- 🚀 An easy‑to‑use tool for working with the `openbq` framework.
- 🖥️ Compatible with macOS, Linux, and Windows.

## Prerequisites

- [Docker](https://www.docker.com/)

## Quick Start

1. Install

    ```sh
    pip install openbq
    ```

2. Display version info

    ```sh
    openbq --version
    ```

3. Validate installation (run benchmarking task)

    ```sh
    openbq --benchmark
    ```

4. Run biometric quality assessment

    ```sh
    openbq --mode face --input data/face
    ```

5. Run biometric quality assessment and compile a EDA report

    ```sh
    openbq --mode fingerprint --input data/fingerprint --report
    ```

## Option flags

| Flag | Description |
| --- | --- |
| --help | Print help info. |
| --version, -V | Display version info. |
| --update, -U | Update `openbq` backend service container. |
| --uninstall | Uninstall `openbq`. |

> Please refer to the [openbq](https://docs.openbq.io/) documentations for further details.
