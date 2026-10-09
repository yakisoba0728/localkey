# Pinned stock Debian ARM64 Chromium; separate chroot avoids mixing distro ABIs.
FROM debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 AS chromium_runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium=154.0.8037.92-1~deb13u1 chromium-common=154.0.8037.92-1~deb13u1 ca-certificates \
    && mkdir -p /opt/ske-chromium-provenance \
    && apt-cache policy chromium chromium-common > /opt/ske-chromium-provenance/apt-policy.txt \
    && dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /opt/ske-chromium-provenance/packages.tsv \
    && sha256sum /usr/lib/chromium/chromium > /opt/ske-chromium-provenance/executable.sha256 \
    && echo '4f8459f639cd128f701fc84b04bbdc496a56202cdd78beec5db721bdda260911  /usr/lib/chromium/chromium' | sha256sum --check \
    && /usr/lib/chromium/chromium --version > /opt/ske-chromium-provenance/version.txt \
    && rm -rf /var/lib/apt/lists/*

# Private builder for an isolated ARM64 Linux guest. No host devices passed in.
# The Docker Desktop kernel itself omits UHID/HIDRAW, so a separate distro kernel
# is required to verify the emulator through actual kernel HID interfaces.
FROM ubuntu:24.04 AS native_runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake ninja-build g++-14 libssl-dev libudev-dev pkg-config \
    python3 python3-venv python3-pip qemu-system-arm cpio gzip busybox-static \
    kmod linux-image-6.8.0-146-generic linux-modules-extra-6.8.0-146-generic curl \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/ske-venv \
    && /opt/ske-venv/bin/pip install --no-cache-dir fido2==2.2.1 cryptography==50.0.0

# CMake FetchContent clones the pinned upstream Catch2 tag.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite-dev pcscd swig python3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN CC=gcc-14 CXX=g++-14 /opt/ske-venv/bin/pip install --no-cache-dir \
    yubikey-manager==5.9.2 pyscard==2.3.1 yubihsm==3.1.2

# Own virtual USB bus in the guest, never modules or devices on the host.
# The official distro omits dummy_hcd; compile the pinned upstream source
# against its exact exported headers/symbol versions for this test kernel.
RUN apt-get update && apt-get install -y --no-install-recommends \
    linux-headers-6.8.0-146-generic libccid libusb-1.0-0-dev make \
    && rm -rf /var/lib/apt/lists/*
RUN /opt/ske-venv/bin/pip install --no-cache-dir pyusb==1.3.1
RUN mkdir -p /opt/ske-dummy-module \
    && curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/usb/gadget/udc/dummy_hcd.c \
       -o /opt/ske-dummy-module/dummy_hcd.c \
    && echo '6892efeaca7d13e0f8ba172fac6b9607f9ac5c60de1a5f1812a57eb7998fd993  /opt/ske-dummy-module/dummy_hcd.c' | sha256sum --check \
    && printf 'obj-m := dummy_hcd.o\n' > /opt/ske-dummy-module/Makefile \
    && make -C /lib/modules/6.8.0-146-generic/build M=/opt/ske-dummy-module CC=gcc-14 LD=ld modules

WORKDIR /work

# pcscd listens for processed udev events; native USB removal/addition needs
# the standard service in the private guest, not just initial sysfs discovery.
RUN apt-get update && apt-get install -y --no-install-recommends udev \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgtk-3-0t64 libasound2t64 libx11-xcb1 libdbus-glib-1-2 libxt6t64 \
    libegl1 libgl1 libpci3 xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fL --retry 3 https://archive.mozilla.org/pub/firefox/releases/157.0.1/linux-aarch64/en-US/firefox-157.0.1.tar.xz -o /tmp/firefox.tar.xz \
    && curl -fL --retry 3 https://archive.mozilla.org/pub/firefox/releases/157.0.1/SHA512SUMS -o /tmp/SHA512SUMS \
    && python3 -c 'import hashlib,pathlib;rows=pathlib.Path("/tmp/SHA512SUMS").read_text().splitlines();a=[r.split()[0] for r in rows if r.split()[-1]=="linux-aarch64/en-US/firefox-157.0.1.tar.xz"];assert len(a)==1;assert hashlib.sha512(pathlib.Path("/tmp/firefox.tar.xz").read_bytes()).hexdigest()==a[0]' \
    && mkdir -p /opt/ske-browser \
    && tar -xJf /tmp/firefox.tar.xz -C /opt/ske-browser \
    && sha256sum /tmp/firefox.tar.xz > /opt/ske-browser/archive.sha256 \
    && rm /tmp/firefox.tar.xz /tmp/SHA512SUMS
RUN /opt/ske-browser/firefox/firefox --version

# Optional virtual-controller policy; preserves function-requested addresses.
# The driver remains a separately licensed GPL kernel component. Base source
# above is upstream SHA-pinned; git apply rejects mismatched patch context.
COPY dummy_hcd-addresses.patch /opt/ske-dummy-module/dummy_hcd-addresses.patch
RUN cd /opt/ske-dummy-module \
    && git apply --check dummy_hcd-addresses.patch \
    && git apply dummy_hcd-addresses.patch \
    && make -C /lib/modules/6.8.0-146-generic/build M=/opt/ske-dummy-module CC=gcc-14 LD=ld modules \
    && python3 -c 'import hashlib,json,pathlib;p=pathlib.Path("/opt/ske-dummy-module");d={"base_source_url":"https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/usb/gadget/udc/dummy_hcd.c","base_source_sha256":"6892efeaca7d13e0f8ba172fac6b9607f9ac5c60de1a5f1812a57eb7998fd993","source_license":"GPL","optional_parameter":"requested_ep_addresses","default_enabled":False,"files":{n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ["dummy_hcd.c","dummy_hcd-addresses.patch","dummy_hcd.ko"]}};(p/"provenance.json").write_text(json.dumps(d,indent=2)+"\n")'

# Actual private desktop UI for PIN dialogs; no host X server or input devices.
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb xdotool x11-utils dbus-x11 at-spi2-core python3-pyatspi \
    && rm -rf /var/lib/apt/lists/*
COPY --from=chromium_runtime / /opt/ske-chromium-root/
