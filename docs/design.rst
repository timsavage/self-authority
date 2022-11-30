Design
######

Requirements
------------

- Self signed CA certificate
  
  - Generate a CSR for creating/renewing certificate

  - Generate private keys for certificate (passcode required)

  - Generate and self sign certificate (defaults to 10 years)

  - Renew certificate

  - Export certificate in PEM and DER formats for installation

  - Display summary of certificate

- Domain certificates (for use with HTTPS)

  - Generate a CSR for creating/renewing certificate

  - Edit CSR contents to update any changed details

  - Generate private keys for certificate

  - Generate and sign certificate (defaults to 1 year the standard most browsers accept)

  - Renew certificate

  - Export certificate in PEM and DER formats

  - Export private keys in PEM and DER formats

  - Delete domain

  - Ping domain to check if certificate is still valid

  - Display summary of certificate

- Common behaviours

  - Save history of certificates

  - Store all data in PEM format to allow for storage in GIT (or other source control system)

  - Don't hold unencrypted keys in memory longer than nessaray

  - Multiple interfaces (CLI, TUI, GUI)



Repository structure
--------------------

Data will be stored in the following structure::

  Repository Root
  ├─ .ca
  │  ├─ ca.crt.pem
  │  ├─ ca-ISODATE-crt.pem
  │  ├─ ca.key.pem
  │  └─ config.toml
  │
  └─ DOMAIN
     ├─ domain.crt.pem
     ├─ domain-ISODATE.crt.pem
     ├─ domain.csr.pem
     ├─ domain.key.pem
     └─ config.toml


Development tools
-----------------

- Python 3.8+

- Cryptography (for all certificate operations)

- Textural/Rich - TUI and CLI interactions

- pyApp - CLI interface and tooling

- odin - Datastructures and validation

