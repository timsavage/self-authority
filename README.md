# Self Authority

A simple tool for managing your own Certificate Authority.

The primary use-case is for assigning certificates to services around your home 
or small office lab that does not require a publicly signed certificate.

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

Initialise your certificate authority:
```shell
> python -m sa.cli ca init .
```

Create a domain name and have it signed:
```shell
> python -m sa.cli domain add
```

Renew a certificate for a domain name
```shell
> python -m sa.cli domain renew MY_DOMAIN
```
