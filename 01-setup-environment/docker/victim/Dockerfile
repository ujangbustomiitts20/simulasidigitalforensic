FROM ubuntu:22.04

LABEL maintainer="Forensik Lab"
LABEL description="Victim Web Server for Digital Forensic Simulation"

ENV DEBIAN_FRONTEND=noninteractive

# Install packages
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    php-mysql \
    php-curl \
    libapache2-mod-php \
    openssh-server \
    rsyslog \
    auditd \
    tcpdump \
    net-tools \
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure Apache
RUN a2enmod rewrite headers

# Create web directory
COPY www/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:rootpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Configure logging
RUN mkdir -p /var/log/forensic

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 22

CMD ["/start.sh"]
