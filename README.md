# revtrvp

This is the documentation for adding a source to the reverse traceroute system. 

## Prerequisites
The source should have a public IP address, as it must be listening for spoofed ICMP packets. Otherwise if the source is behind a NAT, you have to configure the NAT to forward ICMP packets to the source. 

Install docker on the source.  

## Build

In the plvp.config file, please change the value of the interface your source is using to connect to the internet.

Then build the Docker container from the revtrvp directory:

```
docker build -t revtrvp .
```

## Add the source to the system

First, you need to send an email to reverse.traceroute@gmail.com. In this email, provide the public IP address, your name, and your email, and a brief statement of why you want to add your source to the system. 
If we can authenticate you, then we'll send you an email to tell you that your name has been added to our authorized users and an API key to run reverse traceroutes measurements. 

Then, we need to check if your source is capable of receiving reverse traceroutes. We check if it can receive ping RR (spoofed) packets, send pings and traceroutes.
  
Run the following command to start the plvp container, this will connect your source to the controller and starts the tests. You will receive two emails if your source can receive reverse traceroutes: one that states that your source is or is not able to receive reverse traceroutes and one stating that the node is ready. 

```
docker run --name=plvp --net=host --restart=unless-stopped -d --log-opt max-size=1g --log-opt max-file=1 -p 4381:4381 revtrvp /root.crt /plvp.config -loglevel debug"
```

## Bootstrapping the traceroute atlas to your source

To benefit from the full functionnality of the revtr 2.0, you need to bootstrap your source by running traceroutes to your source and RR pings to the traceroute hops revealed by these traceroutes to your source. 

Just curl the following URL (hidden for double blind policy):

```
curl -X POST -H 'Revtr-Key: your api-key' -H source:your-source-ip-address https://hidden-url/api/v1/atlas/run
```

If it is the first time your source is being added to the system, we provide the RIPE Atlas credits for you to run these traceroutes. Otherwise you would have to put a RIPE Atlas key in the request.

```
curl -X POST -H 'Revtr-Key: your-api-key' -H 'RIPE-Key: your-ripe-key' -H source:your-source-ip-address https://hidden-url/api/v1/atlas/run
```

This operation should take 20 minutes to perform, the time for the RIPE Atlas traceroutes and the RR pings to complete.

## Testing reverse traceroute to your source
Once the atlas has been bootstrapped, you can run:

python3 test_reverse_traceroute.py  your_source_ip_addres


