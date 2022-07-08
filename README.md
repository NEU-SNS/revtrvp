# Setting up a Reverse Traceroute source

This is the documentation for adding a source to the Reverse Traceroute
system.  Hosting a source is required to measure a reverse traceroute,
as we need to receive measurement probes sent toward the source to
splice together hops into a complete route.  Once set-up, a source can
be used to measure reverse traceroutes from arbitrary destinations.

## Prerequisites

The Reverse Traceroute source listens for spoofed ICMP packets.  The
source should either have a public IP address or, if it is behind a NAT,
should be forwarded all ICMP packets arriving at the NAT.  The ICMP
packets received by the Reverse Traceroute source contain IP Record
Route options, so the source's hosting network (and upstream networks)
should not filter out or drop packets with IP options.

## Build the Docker container

The Reverse Traceroute software is packaged as a Docker container.  You
will need to install Docker on your machine following instructions for
your operating system and distribution.

The source's configuration is in the `plvp.config` YAML file.  You
should not to need to change anything, but we discuss two parameters:

* `local.interface` is the name of the interface inside the container
  where packets will be received.  The Reverse Traceroute source will
  listen for ICMP packets arriving on this interface and report them to
  the central controller.  You may need to change this to the name of
  the interface on the machine that will run the container.  (More on
  this below.)
* `scamper.rate` controls the maximum probing rate for the source.  The
  default is 100 pps, which should be enough for running tens of
  concurrent reverse traceroutes.  Large measurement campaigns running
  a larger number of concurrent measurements require increasing the
  probing rate.  (Of course, check with your upstream networks and
  notify the Reverse Traceroute operators before increasing the probing
  rate.)
* `scamper.port` is the local port used by the source to receive
  commands from the central controller.  You can keep it at the default
  value.  This port needs to be forwarded into the container when
  running it.
* `local.host`, `local.pprofaddr`, `scamper.host` point to the central
  Reverse Traceroute controller.  These values can be kept fixed, but
  would need to be updated when connecting a source to an alternate
  Reverse Traceroute deployment.

You can build the Docker container running `docker build -t <tag> .`
inside the repository's root directory.  Set a `tag` to more easily
launch the container later.

## Add the source to the system

The Reverse Traceroute controller maintains a list of authorized
sources.  To add your source to the system, you will need to email
reverse.traceroute@gmail.com.  Provide the public IP address, a
description of where that IP is hosted, your name, and your email, and a
brief statement of why you want to add your source to the system.
Prefer to use an institutional e-mail, which helps operators clear new
sources.

After your source is cleared, Reverse Traceroute operators will e-mail
you informing that your source's IP address has been added to the set of
authorized sources.  The e-mail will also contain an API key to launch
reverse traceroute measurements.

## Run the Reverse Traceroute source

As explained under "Prerequisites" above, a Reverse Traceroute source
needs to receive responses to spoofed ICMP probes sent by other vantage
points in the Reverse Traceroute system.  However, Docker runs
containers behind a NAT by default, which will interfere with receiving
the responses to spoofed ICMP probes.  You can work around this issue in
different ways, the easiest is to just run the Docker container with
`--net=host`, which will attach the container on the same network
namespace as the host's.  This will allow the Docker container to access
the host's interface directly and capture any ICMP responses.  (You may
need to change the `local.interface` configuration parameter in
`plvp.config` to point the host's interface, as explained under "Build
the Docker container" above.)

Run the following command to start the container on the host's
namespace.  The `<tag>` parameter is the one you chose when building the
container, and `4381` is the value of `scamper.port` in the
`plvp.config` configuration file.

``` {bash}
docker run --name=<name> --net=host --restart=unless-stopped \
        --detach --log-opt max-size=1g --log-opt max-file=1 \
        --publish 4381:4381
        <tag> /root.crt /plvp.config -loglevel debug
```

This will launch your container, which will connect to the controller on
startup.  Whenever your source connects to the system, the controller
tests if your source is capable of receiving packets containing the IP
Record Route option as well as sending pings and traceroutes.  An e-mail
will be sent to you after the tests complete with a report on whether
your sources can receive reverse traceroutes.  If your source can
receive reverse traceroutes, you will also receive a second e-mail
stating that your source is ready after it's been integrated into the
system.

## Bootstrapping the traceroute atlas to your source

To benefit from the full functionality of Reverse Traceroute, we need to
bootstrap your source by building an atlas of forward traceroutes
towards it from public vantage points, then running Record Route pings
to the traceroute hops revealed by traceroutes toward your source to
support IP aliasing.

If this is the first time your source is being added to the system, we
provide the RIPE Atlas credits for the traceroutes.  You can use the
following REST request to run measurements to update the atlas towards
your source:

``` bash
curl -X POST \
        -H 'Revtr-Key: <your-api-key>' \
        -H source:<your-source-ip-address> \
        https://<controller-hostname>/api/v1/atlas/run
```

Where `<your-api-key>` is the key you received over e-mail from the
Reverse Traceroute operators.  The `<controller-hostname>` is just the
hostname of the server running the central controller, but anonymized
for double-blind review.

For subsequent refreshes of the atlas to your source, you need to
provide a RIPE Atlas API key.  This key should have permissions to
create traceroute requests.  Refreshing the atlas to a source uses
around 60K RIPE Atlas credits.

``` bash
curl -X POST \
        -H 'Revtr-Key: <your-api-key>' \
        -H source:<your-source-ip-address> \
        -H 'RIPE-Key: <your-ripe-atlas-key>' \
        https://<controller-hostname>/api/v1/atlas/run
```

Refreshing the atlas involves waiting for RIPE Atlas traceroutes and
Record Route pings.  It currently takes around 20 minutes.

## Running reverse traceroutes toward your source

You can send a REST API request to the `/api/v1/revtr` endpoint to issue
a reverse traceroute toward your source.  You should pass your API key
and a JSON object specifying the measurements.  The payload should be a
JSON object with a `revtrs` key containing a list of source-destination
pairs.  Each source-destination pair should be specified as a JSON
object with `src` and `dst` keys.  In the example below, a single
reverse traceroute would be issued from 1.1.1.1 towards your source:

``` {bash}
curl -X POST -k \
        -H "Revtr-Key: <your-api-key>" \
        https://<controller-hostname>/api/v1/revtr \
        --data '{"revtrs":[{"src":"<your-source-ip-address>", \
                            "dst":"1.1.1.1"}]}'
```
