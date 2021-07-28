
FROM ubuntu:18.04 as build_scamper

RUN ls -l
RUN mkdir -p scamper-src && cd scamper-src && \
    wget http://www.ccs.neu.edu/home/rhansen2/scamper.tar.gz && \
    tar xzf scamper.tar.gz && cd scamper-cvs-20150901
WORKDIR /scamper-src/scamper-cvs-20150901/
RUN ./configure && make install

RUN apt-get update
RUN apt-get install -y tcpdump 
#RUN apt-get -y install cron 
RUN apt-get -y install python3
RUN apt-get -y install ca-certificates

# All code/tools for traffic monitoring go here
#RUN mkdir /traffic_monitoring

# tcpdump is added to sbin--any other workaround than this?
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump 

# Copy entrypoint script
#COPY entrypoint.sh /entrypoint.sh
#RUN chmod +x /entrypoint.sh

# Copy traffic monitoring scripts
#COPY traffic_monitoring/traffic_listener_cron.sh /traffic_monitoring/traffic_listener_cron.sh
#COPY traffic_monitoring/send_email.py /traffic_monitoring/send_email.py
#RUN chmod 0744 /traffic_monitoring/traffic_listener_cron.sh
#RUN chmod 0744 /traffic_monitoring/send_email.py

# Create cron log file 
#RUN touch /var/log/cron.log

RUN dpkg --add-architecture i386

RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libc6:i386 \
    libncurses5:i386 \
    libstdc++6:i386 \
    iputils-ping \
    inetutils-traceroute \
    init-system-helpers \
&&  apt-get clean \
&&  rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y make coreutils autoconf libtool git build-essential wget && \
    apt-get clean && \
    rm -rf /var/lib/opt/lists/*

FROM golang:1.13 as build_revtrvp
ADD . /go/src/github.com/NEU-SNS/revtrvp
WORKDIR /go/src/github.com/NEU-SNS/revtrvp
RUN go build -o revtrvp .
RUN chmod -R a+rx /go/src/github.com/NEU-SNS/revtrvp/revtrvp


#WORKDIR /plvp
#COPY . /plvp

#RUN useradd -ms /bin/bash plvp
FROM ubuntu:18.04



COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/revtrvp /
COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/root.crt /
COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/plvp.config /
COPY --from=build_scamper /usr/local/bin/scamper /usr/local/bin

RUN ldconfig
RUN which scamper
WORKDIR /

ENTRYPOINT ["/revtrvp"]
CMD ["/root.crt", "plvp.config", "-loglevel", "error"]

EXPOSE 4381
