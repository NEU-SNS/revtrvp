# Introduction

This is the documenation for using the REVTR 2.0 system. You can either run reverse traceroutes from destinations back to a M-Lab source using the [API](#api), or back to your own source by [adding it](#setting-up-a-reverse-traceroute-source)
to the REVTR 2.0 system.

# API

Currently, we give access to our RESTful API provided that you contacted us at <revtr@ccs.neu.edu> and we gave you an API key.

``` {bash}
curl -X POST -k -H "Revtr-Key: <your-api-key>" https://revtr.ccs.neu.edu/api/v1/revtr --data '{"revtrs":[{"src":"<source-ip-address>", "dst":"<destination-ip-address>", "label":"<label>"}]}'
```

The label will server to retrieve your measurements, so put something like a unique ID
and/or your name.

To find the available sources, you can use this query:

``` {bash}
curl -X GET -k -H "Revtr-Key: <your-api-key>" https://revtr.ccs.neu.edu/api/v1/sources
```

## Fetching the results of your reverse traceroutes

We are uploading all the finished reverse traceroutes to M-Lab archive every 10 minutes,
so you should wait about 10-15 minutes after you started your last reverse traceroute
measurement before it gets uploaded.
Then, you can download your results [here](https://console.cloud.google.com/storage/browser/thirdparty-revtr-mlab-oti/revtr) on this M-Lab public archive.
You can postfilter your reverse traceroutes using the filter that you provided.

## Interpreting the results of your reverse traceroutes

The results in the M-Lab archive are the jsonl extension, with one
reverse traceroute per line. An example is:

```{json}
{"id": 20525538, "stop_reason": "REACHES", "fail_reason": "", "src": "193.142.125.51", "dst": "91.224.181.97", "runtime": 1113501997, "date": 1669835097, "label": "bgp_survey_no_timestamp_test_load", "revtr_hops": [{"hop_number": 0, "hop_ip": "91.224.181.97", "hop_type": 1, "measurement_id": 0, "rtt": 18365, "rtt_measurement_id": 1774719956, "cidr": null, "asn": null}, {"hop_number": 1, "hop_ip": "87.245.249.121", "hop_type": 5, "measurement_id": 1774718488, "rtt": 18251, "rtt_measurement_id": 1774719952, "cidr": null, "asn": null}, {"hop_number": 2, "hop_ip": "87.245.225.176", "hop_type": 5, "measurement_id": 1774718488, "rtt": 50144, "rtt_measurement_id": 1774719944, "cidr": null, "asn": null}, {"hop_number": 3, "hop_ip": "80.231.65.2", "hop_type": 5, "measurement_id": 1774718488, "rtt": 870, "rtt_measurement_id": 1774719949, "cidr": null, "asn": null}, {"hop_number": 4, "hop_ip": "185.11.76.45", "hop_type": 4, "measurement_id": 2905588, "rtt": 23231, "rtt_measurement_id": 1774719951, "cidr": null, "asn": null}, {"hop_number": 5, "hop_ip": "185.11.76.76", "hop_type": 4, "measurement_id": 2905588, "rtt": 22508, "rtt_measurement_id": 1774719957, "cidr": null, "asn": null}, {"hop_number": 6, "hop_ip": "213.242.112.49", "hop_type": 4, "measurement_id": 2905588, "rtt": 18089, "rtt_measurement_id": 1774719946, "cidr": null, "asn": null}, {"hop_number": 7, "hop_ip": "4.69.159.46", "hop_type": 4, "measurement_id": 2905588, "rtt": 22129, "rtt_measurement_id": 1774719945, "cidr": null, "asn": null}, {"hop_number": 8, "hop_ip": "4.68.74.110", "hop_type": 4, "measurement_id": 2905588, "rtt": 18752, "rtt_measurement_id": 1774719953, "cidr": null, "asn": null}, {"hop_number": 9, "hop_ip": "5.23.30.17", "hop_type": 4, "measurement_id": 2905588, "rtt": 296, "rtt_measurement_id": 1774719955, "cidr": null, "asn": null}, {"hop_number": 10, "hop_ip": "193.142.125.51", "hop_type": 4, "measurement_id": 2905588, "rtt": 22, "rtt_measurement_id": 1774719954, "cidr": null, "asn": null}]}
{"id": 20525506, "stop_reason": "REACHES", "fail_reason": "", "src": "173.205.3.25", "dst": "182.75.124.57", "runtime": 1095979593, "date": 1669835097, "label": "bgp_survey_no_timestamp_test_load", "revtr_hops": [{"hop_number": 0, "hop_ip": "182.75.124.57", "hop_type": 1, "measurement_id": 0, "rtt": 274242, "rtt_measurement_id": 1774720375, "cidr": null, "asn": null}, {"hop_number": 1, "hop_ip": "203.101.87.155", "hop_type": 5, "measurement_id": 1774718425, "rtt": 263928, "rtt_measurement_id": 1774720373, "cidr": null, "asn": null}, {"hop_number": 2, "hop_ip": "173.205.3.25", "hop_type": 5, "measurement_id": 1774718425, "rtt": 34, "rtt_measurement_id": 1774720530, "cidr": null, "asn": null}]}
```

### Fields of a reverse traceroute measurement

|||
|---|---|
| id  | id of the reverse traceroute measurement  |
| src  | source of the reverse traceroute measurement (e.g., an M-Lab source or your own source) |
| dst  | destination of the reverse traceroute measurement  |
| stop_reason  | stopping reason of the measurement (REACHES, or FAILED)  |
| runtime  | time to measure the reverse path (in ns)  |
| date  | starting date of the measurement (UNIX timestamp) |
| label  | label of the measurement  |

### Hop types

The hop types and number are described in the next table. For more details, please refer to the corresponding sections of our [REVTR 2.0 IMC 2022 paper](https://dl.acm.org/doi/pdf/10.1145/3517745.3561422)

| Type | Name  | Description |
|---|---|---|
| 1  | Destination  | The hop of the destination  |
| 2  | Assume symmetry  | **DEPRECATED** This hop was found by running a forward traceroute to the current previous hop and assumed symmetry on the penultimate hop, i.e. the penultimate hop was the next reverse hop |
| 3  |  Intersected traceroute | This hop was found in a traceroute that was intersected by the last hop of type != 3. The intersection was exactly the last hop or an alias of the last hop (Sec.2, Intersecting a traceroute)|
| 4  |  Intersected Record Route atlas | This hop was found in a Record Route hop revealed by our new technique to reveal Record Route interfaces from the traceroute atlas (Sec. 4.1, Q2 and Sec. 4.2). See more details about how to process these hops [here](#more-details-about-processing-hops-of-type-4-intersected-record-route-atlas) |
| 5  |  Record Route | This hop was found using Record Route (Sec.2, Record Route) |
| 6  |  Spoofed Record Route | This hop was found using spoofed Record Route (Sec.2, Record Route) |
| 11  | Assume symmetry Intradomain  | This hop was found by running a forward traceroute to the current previous hop and assumed symmetry on the penultimate hop, i.e. the penultimate hop was the next reverse hop and the two hops are in the **same** AS. This should be considered as a **safe** assumption (see Section 4.4 of the paper).|
| 12  | Assume symmetry Interdomain  | This hop was found by running a forward traceroute to the current previous hop and assumed symmetry on the penultimate hop, i.e. the penultimate hop was the next reverse hop and the two hops are in **different** ASes. This should **NOT** be considered as a **safe** assumption (see Section 4.4 of the paper).|

#### Details about how to interpret hops of type 2, assumed symmetric

We found in our paper that assuming symmetry on the penultimate hop of a forward traceroute is correct in 57% of the cases if the link on which we assume symmetry is interdomain and 90% for intradomain (Sec 4.4).
To let you the possibility to consider or filter out these measurements, we still return the paths measured by REVTR 2.0 with these symmetry assumptions. What we suggest though, is that you run your IP to AS mapping on the path and only keep the paths that consider trustworthy. In the paper, we only kept those with intradomain assumptions of symmetry.

#### Details about how to interpret hops of type 4, Intersected Record Route atlas

When a reverse traceroute intersects the Record Route atlas, as we have incomplete alias information, we might not know exactly where the reverse traceroute intersected the traceroute.
For instance, if the traceroute in atlas was VP -> T1 -> T2 -> T3 -> T4 -> S, where VP and S are our vantage point and our source, then our technique issued Record Route pings from S (or spoofed as S) to T1, T2, T3, and T4. Let us say the ping to T1 reveals R1, and other reveal nothing.
If we know that T1 is an alias of R1, then, when a reverse traceroute intersects R1, we can say the rest of the path is T1 (or R1) -> T2 -> T3 -> T4 -> S. But if we do not have this information, it could be that R1 is an alias of T2, or even T3, if T1 and T2 do not stamp Record Route packets. In that case, we can only say that a future reverse traceroute intersecting in R1 intersected somewhere between T1 and T4.
What you will have in the data in a list of hops of type 4, corresponding to the segment of the traceroute where the reverse traceroute could have intersected.
A trick that we used to narrow down the size of the potential intersected segment is to map IP addresses to their AS, and remove any AS loop from the AS path.

# Setting up a Reverse Traceroute source

This is the documentation for adding a source to the Reverse Traceroute
system.  Hosting a source is required to measure a reverse traceroute,
as we need to receive measurement probes sent toward the source to
splice together hops into a complete route.  Once set-up, a source can
be used to measure reverse traceroutes from arbitrary destinations.

## Prerequisites

First of all, by joining the system, you are allowing our vantage points to use
your source IP address to send packets such that the responses go back to your
source. Your source will listen for responses to the spoofed ICMP packets
(spoofed as your source IP address).

The source should either have a public IP address or, if it is behind a NAT,
should be forwarded all ICMP packets arriving at the NAT. The ICMP
packets received by a Reverse Traceroute source contain IP Record
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
<reverse.traceroute@gmail.com>.  Provide the public IP address, a
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
curl -X POST -k -H "Revtr-Key: <your-api-key>" https://<controller-hostname>/api/v1/revtr --data '{"revtrs":[{"src":"<your-source-ip-address>", "dst":"1.1.1.1"}]}'
```
