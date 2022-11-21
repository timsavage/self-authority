# Self Authority

A simple tool for managing your own Certificate Authority.

The primary use-case is for assigning certificates to services around your home 
or small office lab that do not require publicly signed certificates.

## Install

**Requires**

- Python 3.10+
- Poetry

**Setup**

- Download the archive or checkout the code from GitHub
- Install the requirements with poetry
  ```shell
  > poetry install
  ```

## Usage

Activate poetry:
```shell
> poetry shell
```

Initialise your certificate authority:
```shell
> sa ca init .
```

Create a domain name and have it signed:
```shell
> sa domain add
```

Renew a certificate for a domain name
```shell
> sa domain renew MY_DOMAIN
```

> **Note**
> 
> Help is a always available using `--help` and for any sub command. 
> ```shell
> > sa --help
> ```
