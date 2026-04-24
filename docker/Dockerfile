FROM alpine:latest

RUN apk add --no-cache samba util-linux

# Create the share and mount directories
RUN mkdir -p /share /assets/windows /mnt/windows && \
    chown -R nobody:nobody /share && \
    chmod -R 0777 /share

# Copy the configuration and entrypoint
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose SMB ports
EXPOSE 137/udp 138/udp 139/tcp 445/tcp

# Run entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
