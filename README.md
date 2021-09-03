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
If we can authenticate you, then we'll send you an email to tell you that your name has been added to our authorized users. 

Then, we need to check if your source is capable of receiving reverse traceroutes. We check if it can receive ping RR (spoofed) packets, send pings and traceroutes.
  
Run the following command to start the plvp container, this will connect your source to the controller and starts the tests. You will receive two emails if your source can receive reverse traceroutes: one that states that your source is or is not able to receive reverse traceroutes and one stating that the node is ready. 

"docker run --net=host --restart=unless-stopped -d --log-opt max-size=1g --log-opt max-file=1 -p 4381:4381 revtr/revtrvps /root.crt /plvp.config -loglevel debug"

Then, after receiving the second email, you can try to run reverse traceroute by running:

python3 test_reverse_traceroute.py  your_ip


