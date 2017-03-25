FROM  ubuntu:14.04
MAINTAINER Melinda Shore <melinda.shore@nomountain.net>

RUN set -ex \
    && apt-get update \
    && apt-get install -y curl \
    && apt-get install -y git \
    && apt-get install -y wget \
    && apt-get install -y libssl-dev \
    && curl -fOSL "https://unbound.net/downloads/unbound-1.5.8.tar.gz" \
    && mkdir -p /usr/src/unbound \
    && tar -xzC /usr/src/unbound --strip-components=1 -f unbound-1.5.8.tar.gz \
    && rm unbound-1.5.8.tar.gz \
    && apt-get -y install libidn11-dev \
    && apt-get -y install python-dev \
    && apt-get -y install make \
    && apt-get install -y automake autoconf libtool \
    && apt-get install -y shtool \
    && cd /usr/src/unbound \
    && ./configure \
    && make \
    && make install \
    && ldconfig \
    && cd /usr/src \
    && git clone https://github.com/getdnsapi/getdns.git \
    && cd /usr/src/getdns \
    && git checkout develop \
    && git submodule update --init \
    && libtoolize -ci \
    && autoreconf -fi \
    && ./configure \
    && make \
    && make install \
    && ldconfig \
    && mkdir -p /etc/unbound \
    && cd /etc/unbound \
    && wget http://www.nomountain.net/getdns-root.key \
    && cd /usr/src \
    && git clone https://github.com/getdnsapi/getdns-python-bindings.git \
    && cd /usr/src/getdns-python-bindings \
    && git checkout develop \
    && python setup.py build \
    && python setup.py install 


CMD ["/usr/bin/python"]
