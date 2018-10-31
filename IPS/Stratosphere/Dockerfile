#
# Stratosphere IPS Dockerfile
#
# https://github.com/stratosphereips/StratosphereLinuxIPS
#
# Build with:
# docker build -t slips .

# Pull base image.
FROM ubuntu:latest

ENV DEBIAN_FRONTEND noninteractive

# Install slips and argus client.
RUN \
  apt-get update && \
  apt-get install -y --no-install-recommends apt-utils
RUN \
  apt-get update && \
  apt-get install -y software-properties-common && \
  apt-get install -y net-tools && \
  apt-get install -y git && \
  rm -rf /var/lib/apt/lists/* && \
  apt-get update && \
  apt-get install -y argus-server && \
  apt-get install -y argus-client && \
  apt-get install -y python2.7 && \
  apt-get install -y iptables && \
  mkdir /home/ubuntu && \
  git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git /home/ubuntu/StratosphereLinuxIPS && \
  git clone https://github.com/stratosphereips/StratosphereTestingFramework /home/ubuntu/StratosphereTestingFramework
RUN \
  apt-get install -y wget && \
  apt-get install -y curl
RUN \
  curl https://qosient.com/argus/src/argus-3.0.8.2.tar.gz --create-dirs -o /home/ubuntu/argus-3.0.8.2.tar.gz && \
  curl https://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz --create-dirs -o /home/ubuntu/argus-clients-3.0.8.2.tar.gz && \
  cd /home/ubuntu
RUN \
  tar -xzvf /home/ubuntu/argus-clients-3.0.8.2.tar.gz -C /home/ubuntu/ && \
  tar -xzvf /home/ubuntu/argus-3.0.8.2.tar.gz -C /home/ubuntu/
RUN \
  apt-get update && \
  apt-get install --fix-missing -y wireshark-common
RUN \
  apt-get install -y tshark tcpdump libpcap0.8-dev flex bison && \
  apt-get install -y make && \
  apt-get install -y vim && \
  apt-get install -y build-essential gcc
RUN apt-get install -y libncurses5-dev libncurses5-dev
RUN apt-get install -y make libgeoip-dev zlib1g-dev libreadline7 libreadline6-dev libbsd-dev libwrap0-dev
RUN sh /home/ubuntu/argus-3.0.8.2/configure
WORKDIR /home/ubuntu/argus-3.0.8.2/
RUN ./configure && make clean && make install
WORKDIR /home/ubuntu/argus-clients-3.0.8.2/
RUN ./configure && make clean && make install
RUN ls -la /home/ubuntu/argus-clients-3.0.8.2/
RUN apt-get install -y python-dateutil
#  sed -i -e 's/ARGUS_MONITOR_ID=\x27hostname\x27/ARGUS_MONITOR_ID=10/g' /etc/argus.conf && \
#  ra -F StratosphereLinuxIPS/ra.conf -n -Z -S -d 172.18.0.2:561 | python2.7 StratosphereLinuxIPS/slips.py -f StratosphereLinuxIPS/models -d

# Expose ports.
EXPOSE 561



#wget http://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz -O /home/
#cd /home/
#tar xvzf argus-clients-3.0.8.2

#ra -F StratosphereLinuxIPS/ra.conf -n -Z b -S 172.18.0.4:561 | python2.7 StratosphereLinuxIPS/slips.py -f StratosphereLinuxIPS/models -d
