FROM alpine:3.19

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    bash \
    inotify-tools \
    rclone \
    openssl \
    curl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/config"]

ENTRYPOINT ["/entrypoint.sh"]
