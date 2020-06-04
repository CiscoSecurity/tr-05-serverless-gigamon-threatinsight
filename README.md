[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-gigamon-threatinsight.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-gigamon-threatinsight)

# Gigamon ThreatINSIGHT Relay API

A sample Relay API implementation using the
[Gigamon ThreatINSIGHT API](https://portal.icebrg.io/help/api)
as an example of a third-party Threat Intelligence service provider.

The API itself is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Testing

```bash
pip install -U -r test-requirements.txt
```

- Check for *PEP 8* compliance: `flake8 .`.
- Run the suite of unit tests: `pytest -v tests/unit/`.

## Deployment

```bash
pip install -U -r deploy-requirements.txt
```

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Usage

```bash
pip install -U -r use-requirements.txt
```

```bash
export URL=<...>
export JWT=<...>

http POST "${URL}"/health Authorization:"Bearer ${JWT}"
http POST "${URL}"/observe/observables Authorization:"Bearer ${JWT}" < observables.json
```

## JWT

```json
{
  "key": "<GTI_API_KEY>"
}
```

Check the full guide on
[JWT](https://github.com/CiscoSecurity/tr-05-serverless-relay#jwt)
encoding/decoding for more details.

## Environment Variables

Besides the common set of environment variables that have the same meaning for
any Relay API (e.g. `SECRET_KEY`), the GTI Relay API also supports the
following ones:

- `CTR_ENTITIES_LIMIT`
  - Restricts the maximum number of CTIM entities of each type returned in a
  single response per each requested observable.
  - Applies to: `Indicator`, `Sighting`.
  - Must be a positive integer. Defaults to `100` (if unset or incorrect). Has
  the upper bound of `1000` to avoid getting overwhelmed with too much data, so
  any greater values are still acceptable but also limited at the same time.

- `GTI_ALLOW_TEST_ACCOUNTS`
  - Allows fake data from the test accounts (`Demo` and `Training`) to be
  returned along with real data (if enabled).
  - Must be a boolean flag represented as an integer (`0` or `1`). Defaults to
  `0` (if unset or incorrect).
