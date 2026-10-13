ARG DESKTOP_PLATFORM=linux/arm64
FROM --platform=${DESKTOP_PLATFORM} debian:trixie-slim AS desktop
ARG DESKTOP_ARCH=aarch64
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd-sysv dbus dbus-x11 udev kmod sudo polkitd pkexec lxpolkit \
    lightdm xfce4-session xfwm4 xfce4-panel xfdesktop4 xfce4-settings \
    xserver-xorg-core xserver-xorg-video-dummy xauth x11-utils xdotool scrot \
    fonts-dejavu fonts-liberation \
    chromium chromium-driver firefox-esr python3-selenium python3-fido2 python3-tk \
    fido2-tools python3-pil curl ca-certificates procps iproute2 kbd openssh-server \
    && if [ "$DESKTOP_ARCH" = x86_64 ]; then apt-get install -y --no-install-recommends linux-image-amd64 initramfs-tools; fi \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash -G sudo lkdesktop \
    && echo 'lkdesktop:localkey-test-only' | chpasswd \
    && echo 'root:localkey-root-test-only' | chpasswd \
    && mkdir -p /etc/lightdm/lightdm.conf.d /home/lkdesktop/.config/autostart /localkey/results \
    && printf '[LightDM]\nlogind-check-graphical=false\n[Seat:*]\nautologin-user=lkdesktop\nautologin-user-timeout=0\nuser-session=xfce\nxserver-command=X -config /etc/X11/xorg-localkey.conf -noreset -nolisten tcp\n' \
       > /etc/lightdm/lightdm.conf.d/localkey-test.conf \
    && systemctl enable lightdm.service \
    && systemctl set-default graphical.target \
    && rm -f /etc/machine-id /var/lib/dbus/machine-id \
    && touch /etc/machine-id
RUN mkdir -p /home/lkdesktop/.ssh /etc/ssh/sshd_config.d \
    && chmod 0700 /home/lkdesktop/.ssh \
    && chown lkdesktop:lkdesktop /home/lkdesktop/.ssh \
    && printf 'ListenAddress 127.0.0.1\nPasswordAuthentication no\nPermitRootLogin no\nUsePAM yes\n' > /etc/ssh/sshd_config.d/localkey-test.conf \
    && systemctl disable ssh.service ssh.socket
COPY xorg.conf /etc/X11/xorg-localkey.conf
COPY session.desktop /home/lkdesktop/.config/autostart/localkey-test.desktop
COPY session.sh /localkey/session.sh
COPY loopback.service /etc/systemd/system/localkey-loopback.service
RUN chown -R lkdesktop:lkdesktop /home/lkdesktop/.config \
    && chmod 0755 /localkey/session.sh \
    && mkdir -p /localkey/results && chmod 0777 /localkey/results \
    && systemctl enable localkey-loopback.service

FROM localkey-guest-build:1 AS kernel

FROM debian:trixie-slim
ARG DESKTOP_ARCH=aarch64
RUN apt-get update && apt-get install -y --no-install-recommends \
    e2fsprogs cpio qemu-system-arm qemu-system-x86 qemu-utils kmod gzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=desktop / /rootfs/
COPY --from=kernel /opt/localkey-guest /kernel/
# Reuse the exact kernel/module pair from the transport guest; no host devices.
RUN if [ "$DESKTOP_ARCH" = x86_64 ]; then \
        cp /rootfs/boot/vmlinuz-* /kernel/Image; cp /rootfs/boot/initrd.img-* /kernel/initrd; \
    else \
        cd /rootfs && gzip -dc /kernel/base.cpio.gz | cpio -id --quiet 'usr/lib/modules/*' \
        && depmod -b /rootfs "$(cat /kernel/kernel-release)"; \
    fi \
    && rm -f /rootfs/.dockerenv /rootfs/etc/resolv.conf
