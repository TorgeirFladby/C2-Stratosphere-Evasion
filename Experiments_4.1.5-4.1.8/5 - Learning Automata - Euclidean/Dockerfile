#
# Stratosphere IPS Dockerfile
#
# https://github.com/stratosphereips/StratosphereLinuxIPS
#
# Build with:
# docker build -t slips-experiments /path/to/Dockerfile/folder

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
  apt-get install -y python2.7 && \
  apt-get install -y iptables && \
  mkdir /home/ubuntu
WORKDIR /home/ubuntu/
RUN \
  git clone --single-branch -b develop https://github.com/stratosphereips/StratosphereLinuxIPS.git && \
  git clone https://github.com/stratosphereips/StratosphereTestingFramework
RUN \
  apt-get install -y wget && \
  apt-get install -y curl
RUN \
  curl https://qosient.com/argus/src/argus-3.0.8.2.tar.gz --create-dirs -o /home/ubuntu/argus-3.0.8.2.tar.gz && \
  curl https://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz --create-dirs -o /home/ubuntu/argus-clients-3.0.8.2.tar.gz
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
RUN ./configure && make && make install
WORKDIR /home/ubuntu/argus-clients-3.0.8.2/
RUN ./configure && make && make install
RUN ls -la /home/ubuntu/argus-clients-3.0.8.2/
RUN apt-get install -y python-dateutil
RUN apt-get install -y python-pip
RUN pip install prettytable zodb transaction btrees persistent scapy numpy matplotlib pandas
WORKDIR /home/ubuntu
RUN mkdir SlipsExperiments
WORKDIR /home/ubuntu/SlipsExperiments
RUN apt-get -y install python-tk
RUN mkdir trials
ADD stf /home/ubuntu/SlipsExperiments/stf/
ADD pcaps/*.pcap /home/ubuntu/SlipsExperiments/trials/
RUN mkdir confs
RUN mkdir data
RUN cp /home/ubuntu/StratosphereTestingFramework/confs/ra.conf confs/
ADD change_pcap_timestamps.py /home/ubuntu/SlipsExperiments/
ADD perturbation_optimizer.py /home/ubuntu/SlipsExperiments/
ADD la_slips.py / /home/ubuntu/SlipsExperiments/
ADD stf/core/dataset.py /home/ubuntu/SlipsExperiments/stf/core/
ADD stf/core/connections.py /home/ubuntu/SlipsExperiments/stf/core/
ADD docker-entrypoint.sh /home/ubuntu/SlipsExperiments/
RUN chmod +x docker-entrypoint.sh
#RUN python la_slips.py
