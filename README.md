[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")
[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-gigamon-threatinsight.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-gigamon-threatinsight)

# Gigamon ThreatINSIGHT Relay

Concrete Relay implementation using
[Gigamon ThreatINSIGHT](https://www.gigamon.com/products/detect-respond/gigamon-threatinsight.html?utm_campaign=cisco&utm_source=ti-module&utm_medium=referral)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be
easily packaged and deployed as an AWS Lambda Function using
[Zappa](https://github.com/Miserlou/Zappa).

## Rationale

1. We need an application that will translate API requests from SecureX Threat Response
to the third-party integration, and vice versa. This application is provided
here in the GitHub repository, and we are going to install it in AWS Lambda
using Zappa.

2. AWS Lambda allows us to deploy our application without deploying a dedicated
server or paying for so called "idle" cycles. AWS handles instantiation and
resource provisioning; all we need to do is define the access rights and upload
our application.

3. Zappa is a helper tool that will package our application and publish it to
AWS as a Lambda function. It abstracts a large amount of manual configuration
and requires only a very simple configuration file, which we have provided and
will explain how to customize it during this process.

## Step 0: AWS Setup

To get started, you have to set up your AWS environment first by carefully
following the instructions from the [AWS HOWTO](aws/HOWTO.md). In addition, the
document also covers how to configure the [Zappa Settings](zappa_settings.json)
by explaining the relationships between the values there and your AWS setup.

## Step 1: Requirements Installation

First of all, make sure that you already have Python 3 installed by typing
```
python3 --version
```
in your command-line shell.

The application has been implemented and tested using `Python 3.7`. You may try
to use any higher versions if you wish as they should be backward-compatible.

After that, you have to create a "virtual environment" to isolate the
application-specific requirements from the libraries globally installed to your
system. Here are the steps to follow:

1. Create a virtual environment named `venv`:

   `python3 -m venv venv`

2. Activate the virtual environment:
   - Linux/Mac: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate.bat`

3. Upgrade PIP (optional):

   `pip install --upgrade pip`

**NOTE**. The virtual environment has to be created only once, you just have
to make sure to activate it each time you are working on or playing with the
application (modern IDEs can automatically do that for you). You can deactivate
a previously activated virtual environment by simply typing `deactivate` in
your command-line shell.

Finally, install the libraries required for the application to function from
the [requirements.txt](requirements.txt) file:

```
pip install --upgrade --requirement requirements.txt
```

## Step 2: Application Deployment

### AWS Lambda Function

To `deploy` your application to AWS as a Lambda function for the first time,
run the following command:
```
zappa deploy dev
```

**NOTE**. Here `dev` is just the name of the default stage. You may define as
many stages as you like. Each Zappa command requires a stage to be specified so
make sure to replace `dev` with the name of your custom stage when necessary.

**NOTE**. If you are experiencing any problems with running the command then
check the [AWS Common Errors](aws/CommonErrors.md) guide on troubleshooting
of some most common types of errors.

Once the Lambda has been deployed, make sure to save the public `URL` to your
Lambda returned by Zappa. It will look like this:
```
https://<RANDOM_ID>.execute-api.<AWS_REGION>.amazonaws.com/<STAGE>
```

You can check the `status` of your deployment with the corresponding command:
```
zappa status dev
```

Notice that you have to `deploy` your Lambda only once. Each time you make
changes to the source code or to the settings file you just have to `update`
the Lambda by running the following command:
```
zappa update dev
```

As a bonus, you can also monitor your Lambda's HTTP traffic in near real-time
with the `tail` command:
```
zappa tail dev --http
```

If you do not need your Lambda anymore you can run the following command to
get rid of it altogether and clean up the underlying resources:
```
zappa undeploy dev
```

**NOTE**. The `deploy` command always returns a brand new `URL`. The `update`
command does not change the current `URL`. The `undeploy` command destroys the
old `URL` forever.

### SecureX Threat Response Module

Now, the only thing left to do is to follow one of these URLs to navigate 
to SecureX Threat Response page in your region and create the Gigamon ThreatINSIGHT
module using your Lambda's URL and Gigamon ThreatINSIGHT API key:
- US: https://securex.us.security.cisco.com/integrations/available/f4b2cf01-0447-436e-8dc1-b0b15049888b/new
- EU: https://securex.eu.security.cisco.com/integrations/available/cdf11c33-0891-491a-8e36-201e4decd3d0/new
- APJC: https://securex.apjc.security.cisco.com/integrations/available/904e961f-ff81-48f5-aeb0-5c033e2054b7/new 

You will also be prompted to enter next Environment Variables:

  - `CTR_ENTITIES_LIMIT`
    - Restricts the maximum number of CTIM entities of each type returned in a
    single response per each requested observable.
    - Applies to the following CTIM entities:
      - `Indicator`,
      - `Sighting`.
    - Must be a positive integer. Defaults to `100` (if unset or incorrect). Has
    the upper bound of `1000` to avoid getting overwhelmed with too much data, so
    any greater values are still acceptable but also limited at the same time.
   
  - `GTI_ALLOW_TEST_ACCOUNTS`
    - Allows fake data from the test accounts (`Demo` and `Training`) to be
    returned along with real data (if enabled).
    - Must be a boolean flag represented as an integer (`0` or `1`). Defaults to
    `0` (if unset or incorrect).

## Step 3: Testing (Optional)

If you want to test the application you have to install a couple of extra
dependencies from the [test-requirements.txt](test-requirements.txt) file:
```
pip install --upgrade --requirement test-requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and
[PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](observables.json) file.

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Indicator`,
    - `Sighting`,
    - `Relationship`.

- `POST /refer/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Builds a search link per each supported observable to pivot back to the
  underlying external service and look up the observable there.
  - Returns a list of those links.
  
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `ip`
- `domain`
- `md5`
- `sha1`
- `sha256`

### CTIM Mapping Specifics

Each `Sighting` for a supported observable is based on a matching network event
that occurred in your environment and was recorded by GTI sensors. There are
quite a few different event types. Each event type contains both a set of
common fields (included in all event types) and event fields (unique to the
event type). Thus, each particular `Sighting` may have different types of
embedded CTIM relations depending on the actual type of the original event the
`Sighting` is based on.

Besides inspecting your network traffic and extracting key protocol metadata
into events, GTI also provides an alerting mechanism of rules and detections,
notifying you when events matching specific criteria appear in your
environment. Thus, if an event was detected by a rule, then the corresponding
`Sighting` for the given event will also contain additional information about
the given matching rule spread across several CTIM fields.

Since each GTI rule is effectively an `Indicator` in terms of CTIM, each event
detected by a rule will also result in a `Relationship` between the event's
`Sighting` and the matching rule's `Indicator`.
