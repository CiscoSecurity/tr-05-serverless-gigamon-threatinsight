[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# For AWS Serverless Lambda deployment
[AWS Serverless Lambda Code](https://github.com/CiscoSecurity/tr-05-serverless-gigamon-threatinsight/releases/tag/v1.2.1)

# Gigamon ThreatINSIGHT (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using
[Gigamon ThreatINSIGHT](https://www.gigamon.com/products/detect-respond/gigamon-threatinsight.html?utm_campaign=cisco&utm_source=ti-module&utm_medium=referral)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

The code is provided here purely for educational purposes.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)
If you want to test the application you will require Docker and several dependencies from the [requirements.txt](code/requirements.txt) file:
```
pip install --upgrade --requirement code/requirements.txt
```
You can perform two kinds of testing:
- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:
  `cd code`
  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](code/observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-gigamon-threatinsight .
```
 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.
￼
```
docker run -dp 9090:9090 --name tr-05-gigamon-threatinsight tr-05-gigamon-threatinsight
```
 3. Watch the container logs to ensure it starts correctly.
￼
```
docker logs tr-05-gigamon-threatinsight
```
 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.
￼
```
curl http://localhost:9090
```

### SecureX Threat Response Module

Now, the only thing left to do is to follow one of these URLs to navigate 
to SecureX Threat Response page in your region and create the Gigamon ThreatINSIGHT
module using your Lambda's URL and Gigamon ThreatINSIGHT API key:
- US: https://securex.us.security.cisco.com/integrations/available/f4b2cf01-0447-436e-8dc1-b0b15049888b/new
- EU: https://securex.eu.security.cisco.com/integrations/available/cdf11c33-0891-491a-8e36-201e4decd3d0/new
- APJC: https://securex.apjc.security.cisco.com/integrations/available/904e961f-ff81-48f5-aeb0-5c033e2054b7/new 

You will also be prompted to enter `CTR_ENTITIES_LIMIT` variable that:
  - Restricts the maximum number of CTIM entities of each type returned in a
  single response per each requested observable.
  - Applies to the following CTIM entities:
    - `Indicator`,
    - `Sighting`.
  - Must be a positive integer. Defaults to `100` (if unset or incorrect). Has
  the upper bound of `1000` to avoid getting overwhelmed with too much data, so
  any greater values are still acceptable but also limited at the same time.
   
And be prompted to choice option `GTI_ALLOW_TEST_ACCOUNTS`:
  - Allows fake data from the test accounts (`Demo` and `Training`) to be
  returned along with real data (if enabled).


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
