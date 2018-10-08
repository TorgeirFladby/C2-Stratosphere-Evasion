#
# Stratosphere IPS Dockerfile
#
# https://github.com/stratosphereips/StratosphereLinuxIPS
#
# Build with:
# docker build -t slips .

# Pull base image.
FROM ubuntu:16.04

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
  git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
#  sed -i -e 's/ARGUS_MONITOR_ID=\x27hostname\x27/ARGUS_MONITOR_ID=10/g' /etc/argus.conf && \
#  ra -F StratosphereLinuxIPS/ra.conf -n -Z -S -d 172.18.0.2:561 | python2.7 StratosphereLinuxIPS/slips.py -f StratosphereLinuxIPS/models -d

# Expose ports.
EXPOSE 561



#wget http://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz -O /home/
#cd /home/
#tar xvzf argus-clients-3.0.8.2

#ra -F StratosphereLinuxIPS/ra.conf -n -Z b -S 172.18.0.4:561 | python2.7 StratosphereLinuxIPS/slips.py -f StratosphereLinuxIPS/models -d
