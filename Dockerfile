FROM  python:2.7
MAINTAINER Melinda Shore <melinda.shore@nomountain.net>

RUN set -ex \
    && apt-get update \
    && curl -fOSL "https://unbound.net/downloads/unbound-1.5.8.tar.gz" \
    && curl -fOSL "https://github.com/getdnsapi/getdns/archive/v1.0.0b1.tar.gz" \
    && mkdir -p /usr/src/unbound \
    && tar -xzC /usr/src/unbound --strip-components=1 -f unbound-1.5.8.tar.gz \
    && rm unbound-1.5.8.tar.gz \
    && mkdir /usr/src/libgetdns \
    && tar -xzC /usr/src/libgetdns --strip-components=1 -f v1.0.0b1.tar.gz \
    && rm v1.0.0b1.tar.gz \
    && apt-get -y install libidn11-dev \
    && apt-get -y install python-dev \
    && cd /usr/src/unbound \
    && ./configure \
    && make \
    && make install \
    && ldconfig \
    && cd /usr/src/libgetdns \
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
    && git checkout release/v1.0.0b1 \
    && python setup.py build \
    && python setup.py install 


CMD ["python2"]
