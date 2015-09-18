FROM busybox
ADD ./cftp_linux-amd64 /app
CMD ["/app"]
