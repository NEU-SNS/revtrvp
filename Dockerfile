FROM ubuntu:18.04 as build_scamper

ARG PLVP_CONFIG

RUN dpkg --add-architecture i386

RUN apt-get update && \
    apt-get install --yes \
      autoconf \
      build-essential \
      ca-certificates \
      coreutils \
      gcc \
      g++ \
      git \
      inetutils-traceroute \
      init-system-helpers \
      iputils-ping \
      libtool \
      python3 \
      tcpdump \
      vim \
      wget
# RUN apt-get clean && \
# RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p scamper-src && \
    cd scamper-src && \
    # wget http://fring2.khoury.northeastern.edu/scamper-cvs-20211212x.tar.gz && \
    # tar xzf scamper-cvs-20211212x.tar.gz && cd scamper-cvs-20211212x
    wget http://fring2.khoury.northeastern.edu/scamper-cvs-20250401.tar.gz && \
    tar xzf scamper-cvs-20250401.tar.gz && cd scamper-cvs-20250401

# For debugging scamper
# RUN mkdir -p scamper-src
# COPY scamper/scamper-cvs-20150901 /scamper-src/scamper-cvs-20150901

WORKDIR /scamper-src/scamper-cvs-20250401/
# WORKDIR /scamper-src/scamper-cvs-20150901/
RUN apt-get install --yes libc6-dev zlib1g-dev
RUN apt-get install -y libssl-dev
# RUN ./configure --enable-static --disable-shared CFLAGS="-static -lssl -lcrypto -lpthread  -lz -ldl -static-libgcc" LIBS="-lssl -lcrypto -lpthread  -lz -ldl"
RUN ./configure --enable-debug
RUN ls
# RUN make LDFLAGS="-all-static" LIBS="-lssl -lcrypto -lpthread -lm -ldl " -j16
RUN make -j 16
RUN  make install
# RUN apt-get -y install gdb
# RUN ldd scamper/scamper


# tcpdump is added to sbin--any other workaround than this?
# ENV PATH "$PATH:/usr/sbin"

# All code/tools for traffic monitoring go here
#RUN mkdir /traffic_monitoring
#
# Copy entrypoint script
#COPY entrypoint.sh /entrypoint.sh
#RUN chmod +x /entrypoint.sh
#
# Copy traffic monitoring scripts
#COPY traffic_monitoring/traffic_listener_cron.sh /traffic_monitoring/traffic_listener_cron.sh
#COPY traffic_monitoring/send_email.py /traffic_monitoring/send_email.py
#RUN chmod 0744 /traffic_monitoring/traffic_listener_cron.sh
#RUN chmod 0744 /traffic_monitoring/send_email.py
#
# Create cron log file 
#RUN touch /var/log/cron.log

FROM golang:1.19.3 as build_revtrvp

ADD . /go/src/github.com/NEU-SNS/revtrvp
WORKDIR /go/src/github.com/NEU-SNS/revtrvp
RUN go build -o revtrvp .
RUN chmod -R a+rx /go/src/github.com/NEU-SNS/revtrvp/revtrvp

#WORKDIR /plvp
#COPY . /plvp
#RUN useradd -ms /bin/bash plvp

# In case we want to switch to a dynamically linked binary.
# FROM ubuntu:18.04
# RUN apt update
# RUN apt-get install libssl-dev

FROM build_scamper

COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/revtrvp /
# COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/root.crt /
COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/server.crt /
COPY --from=build_revtrvp /go/src/github.com/NEU-SNS/revtrvp/$PLVP_CONFIG  /

# COPY --from=build_scamper /usr/local/bin/scamper /usr/local/bin
# COPY --from=build_scamper /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/

RUN ldconfig
RUN which scamper

# Give the scamper binary all the needed capabilities so that the container
# processes can run as non-root.
#   CHOWN: scamper_privsep_init: could not chown /var/empty: Operation not permitted
#   DAC_OVERRIDE: Could not connect to "/var/local/tcpinfoeventsocket/tcpevents.sock" (error: dial unix /var/local/tcpinfoeventsocket/tcpevents.sock: connect: permission denied)
#   NET_RAW: to be able to talk ICMP
#   SETGID: scamper_privsep_init: could not setgroups: Operation not permitted
#   SETUID: scamper_privsep_init: could not setuid: Operation not permitted
#   SYS_CHROOT: scamper_privsep_init: could not chroot to /var/empty: Operation not permitted
RUN setcap cap_chown,cap_dac_override,cap_net_raw,cap_setgid,cap_setuid,cap_sys_chroot=ep /usr/local/bin/scamper

# The revtrvp process needs to create raw sockets to listen for ICMP packets.
RUN setcap cap_net_raw=ep /revtrvp

WORKDIR /

ENTRYPOINT ["/revtrvp"]
CMD ["/server.crt", $PLVP_CONFIG, "-loglevel", "error"]

EXPOSE 4381


