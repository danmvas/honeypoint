# Scanner for the SC lab: Metasploit + Nmap + rdpscan + tcpdump, one image.
#
#   podman build -t localhost/sc-scanner -f honeyd/lab/scanner.Containerfile honeyd/lab
#
# Base pinned by digest (Rapid7's official image, Alpine, ships nmap).
FROM docker.io/metasploitframework/metasploit-framework@sha256:8096709486bce8b5f35980f2aea42dc7cd83e34ebbeb4d56eab3339847de258d

USER root
RUN apk add --no-cache tcpdump python3 bash ethtool iproute2 iputils \
        netcat-openbsd procps coreutils git build-base

# rdpscan (independent BlueKeep scanner implementation), pinned.
ARG RDPSCAN_COMMIT=09db2719a76d0fbc535f99fb51304ef060c0e484
RUN git clone https://github.com/robertdavidgraham/rdpscan /src/rdpscan \
 && cd /src/rdpscan \
 && git checkout --detach "$RDPSCAN_COMMIT" \
 && make \
 && install -m 0755 rdpscan /usr/local/bin/rdpscan

RUN ln -sf /usr/src/metasploit-framework/msfconsole /usr/local/bin/msfconsole

ENTRYPOINT []
CMD ["sleep", "infinity"]
