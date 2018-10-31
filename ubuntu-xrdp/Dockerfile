FROM ubuntu:18.04 as builder
MAINTAINER Daniel Guerra

# Install packages

ENV DEBIAN_FRONTEND noninteractive
RUN sed -i "s/# deb-src/deb-src/g" /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -yy upgrade
ENV BUILD_DEPS="git autoconf pkg-config libssl-dev libpam0g-dev \
    libx11-dev libxfixes-dev libxrandr-dev nasm xsltproc flex \
    bison libxml2-dev dpkg-dev libcap-dev"
RUN apt-get -yy install  sudo apt-utils software-properties-common $BUILD_DEPS


# Build xrdp

WORKDIR /tmp
RUN apt-get source pulseaudio
RUN apt-get build-dep -yy pulseaudio
WORKDIR /tmp/pulseaudio-11.1
RUN dpkg-buildpackage -rfakeroot -uc -b
WORKDIR /tmp
RUN git clone --branch v0.9.7 --recursive https://github.com/neutrinolabs/xrdp.git
WORKDIR /tmp/xrdp
RUN ./bootstrap
RUN ./configure
RUN make
RUN make install
WORKDIR /tmp/xrdp/sesman/chansrv/pulse
RUN sed -i "s/\/tmp\/pulseaudio\-10\.0/\/tmp\/pulseaudio\-11\.1/g" Makefile
RUN make
RUN mkdir -p /tmp/so
RUN cp *.so /tmp/so

FROM ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt install -yy vim wget ca-certificates xorgxrdp pulseaudio xrdp\
  xfce4 xfce4-terminal xfce4-screenshooter xfce4-taskmanager \
  xfce4-clipman-plugin xfce4-cpugraph-plugin xfce4-netload-plugin \
  xfce4-xkb-plugin xauth supervisor uuid-runtime locales \
  firefox pepperflashplugin-nonfree openssh-server sudo
RUN mkdir -p /var/lib/xrdp-pulseaudio-installer
COPY --from=builder /tmp/so/module-xrdp-source.so /var/lib/xrdp-pulseaudio-installer
COPY --from=builder /tmp/so/module-xrdp-sink.so /var/lib/xrdp-pulseaudio-installer
ADD bin /usr/bin
ADD etc /etc
#ADD pulse /usr/lib/pulse-10.0/modules/

# Configure
RUN mkdir /var/run/dbus
RUN cp /etc/X11/xrdp/xorg.conf /etc/X11
RUN sed -i "s/console/anybody/g" /etc/X11/Xwrapper.config
RUN sed -i "s/xrdp\/xorg/xorg/g" /etc/xrdp/sesman.ini
RUN locale-gen en_US.UTF-8
RUN echo "xfce4-session" > /etc/skel/.Xclients
RUN cp -r /etc/ssh /ssh_orig
RUN rm -rf /etc/ssh/*
RUN rm -rf /etc/xrdp/rsakeys.ini /etc/xrdp/*.pem
RUN apt-get -y update
RUN apt-get install -y --no-install-recommends apt-utils
RUN apt-get install -y software-properties-common
WORKDIR /home
RUN sudo -s
RUN apt-get -y install net-tools
RUN apt-get -y install iptables
RUN apt-get -y install argus-client argus-server
RUN argus -P 561 -d
RUN wget https://discordapp.com/api/download?platform=linux&format=tar.gz
RUN apt-get -y update
RUN apt-get install -y git
RUN git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git /home/ubuntu/StratosphereLinuxIPS
RUN git clone https://github.com/stratosphereips/StratosphereTestingFramework /home/ubuntu/StratosphereTestingFramework
RUN apt-get install -y curl
RUN curl https://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz --create-dirs -o /home/ubuntu/argus-clients-3.0.8.2.tar.gz
RUN tar -xzvf /home/ubuntu/argus-clients-3.0.8.2.tar.gz -C /home/ubuntu/
RUN apt-get -y update
RUN apt-get install -y wireshark-common
RUN apt-get install -y tshark tcpdump libpcap0.8-dev flex bison
RUN apt-get install -y libncurses5-dev libncurses5-dev
RUN apt-get install -y make libgeoip-dev zlib1g-dev libreadline7 libreadline6-dev libbsd-dev libwrap0-dev
RUN apt-get install -y build-essential gcc
WORKDIR /home/ubuntu/argus-clients-3.0.8.2
RUN ./configure && make clean && make install
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update
RUN apt-get install -y python3.6
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip
RUN pip3 install discord asyncio aiohttp

# Make sure to add pupy and related libraries, like rpyc and discord.

# Add sample user

RUN addgroup ubuntu
RUN useradd -m -s /bin/bash -g ubuntu ubuntu
RUN echo "ubuntu:ubuntu" | /usr/sbin/chpasswd
RUN echo "ubuntu    ALL=(ALL) ALL" >> /etc/sudoers

# Docker config

VOLUME ["/etc/ssh","/home"]
EXPOSE 3389 22 9001 561
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["supervisord"]
