FROM alpine:3.14.2 AS stage
LABEL maintainer="Guilherme Freitas <g.fr@tuta.io>"

COPY . .

RUN apk update && apk add make gcc libevent-dev msgpack-c-dev musl-dev bsd-compat-headers jq curl-dev
RUN make && make install && cd ..
RUN sed -i -e 's/"daemonize":.*true,/"daemonize": false,/g' /etc/webdis.prod.json

# main image
FROM alpine:3.14.2
# Required dependencies, with versions fixing known security vulnerabilities
# RUN apk update && apk add libevent msgpack-c 'redis>5.1' 'apk-tools>2.12.6-r0'
RUN apk update && apk add libevent msgpack-c 'redis>6.2.6' 'apk-tools>2.12.6-r0'
COPY --from=stage /usr/local/bin/webdis /usr/local/bin/
COPY --from=stage /etc/webdis.prod.json /etc/webdis.prod.json
RUN echo "daemonize yes" >> /etc/redis.conf
CMD /usr/bin/redis-server /etc/redis.conf && /usr/local/bin/webdis /etc/webdis.prod.json

EXPOSE 7379
