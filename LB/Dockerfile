#
# Nginx Dockerfile
#
# https://github.com/dockerfile/nginx
#
# Build with:
# docker build -t custom-nginx .

# Pull base image.
FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

# Install Nginx.
RUN \
  apt-get update && \
  apt-get install -y --no-install-recommends apt-utils
RUN \
  apt-get update && \
  apt-get install -y software-properties-common && \
  add-apt-repository -y ppa:nginx/stable && \
  apt-get install -y nginx && \
  apt-get install -y net-tools && \
  apt-get install -y git && \
  rm -rf /var/lib/apt/lists/* && \
  echo "\ndaemon off;" >> /etc/nginx/nginx.conf && \
  chown -R www-data:www-data /var/lib/nginx && \
  apt-get update && \
#  apt-get install -y argus-server && \
  apt-get install -y argus-clients && \
  RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y gnupg && \
  cd /home && \
  git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git && \
#  sed -i -e 's/ARGUS_MONITOR_ID=\x27hostname\x27/ARGUS_MONITOR_ID=10/g' /etc/argus.conf && \
  argus -B 172.18.0.2 -F StratosphereLinuxIPS/argus.conf

# Define mountable directories.
VOLUME ["/etc/nginx/sites-enabled", "/etc/nginx/certs", "/etc/nginx/conf.d", "/var/log/nginx", "/var/www/html"]

# Define working directory.
WORKDIR /etc/nginx

# Define default command.
CMD ["nginx"]

# Expose ports.
EXPOSE 80
EXPOSE 443
EXPOSE 561



#wget http://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz -O /home/
#cd /home/
#tar xvzf argus-clients-3.0.8.2
