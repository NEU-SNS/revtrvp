# revtrvp

Build the Docker container, then run:


"docker run --net=host --restart=unless-stopped -d --log-opt max-size=1g --log-opt max-file=1 -p 4381:4381 revtr/revtrvps /root.crt /plvp.config -loglevel debug"
