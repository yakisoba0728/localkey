# localkey-guest-build: the QEMU runner plus the guest's kernel and root filesystem.
#
# Built by tools/linux-guest/build-image.sh (network is used only here, for apt). The final
# image holds qemu-system-aarch64 and, under /opt/localkey-guest/:
#   Image            Ubuntu's generic arm64 kernel as a raw Image (see extract-image.py)
#   base.cpio.gz     the guest root filesystem (Ubuntu userland + the trimmed module set)
#   config, kernel-release, modules.list, rootfs-size
# The guest userland never contains QEMU, compilers or kernel headers: each stage below
# starts from ubuntu:26.04 and only the files named in a COPY cross over.

ARG UBUNTU=ubuntu:26.04

# Kernel ABI, flavour and the matching linux-source package version. Change all three
# together when Ubuntu publishes a new kernel (apt-cache depends linux-image-generic).
ARG KABI=7.0.0-38
ARG KFLAVOUR=generic
ARG KSRC_VERSION=7.0.0-38.38

# Modules the guest loads, with their dependency closure computed by kmod.
ARG MODULES="uhid dummy_hcd libcomposite usb_f_fs usbhid hid_generic usbmon"

########################################################################################
# dummy_hcd: Ubuntu builds its kernel without CONFIG_USB_DUMMY_HCD ("# ... is not set" in
# /boot/config-*), so the virtual host+device controller is compiled here, out of tree,
# from drivers/usb/gadget/udc/dummy_hcd.c of the very linux-source package the kernel was
# built from, against that kernel's headers, with the compiler named in its
# CONFIG_CC_VERSION_TEXT (gcc 15.2.0-16ubuntu1). Every other module the tests use is
# Ubuntu's own build. The module is unsigned; MODULE_SIG_FORCE is off and lockdown applies
# only under secure boot, so it loads and taints the kernel ("module verification failed").
FROM ${UBUNTU} AS dummy-hcd
ARG KABI
ARG KFLAVOUR
ARG KSRC_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        "linux-headers-${KABI}-${KFLAVOUR}" gcc make bzip2 kmod; \
    cd /tmp; \
    upstream="${KABI%-*}"; \
    apt-get download "linux-source-${upstream}=${KSRC_VERSION}"; \
    dpkg-deb -x linux-source-*.deb /tmp/src; \
    rm -f linux-source-*.deb; \
    mkdir /build; \
    tar -xjf /tmp/src/usr/src/linux-source-*/linux-source-*.tar.bz2 -O \
        --wildcards '*/drivers/usb/gadget/udc/dummy_hcd.c' > /build/dummy_hcd.c; \
    rm -rf /tmp/src /var/lib/apt/lists/*; \
    test -s /build/dummy_hcd.c; \
    echo 'obj-m := dummy_hcd.o' > /build/Kbuild; \
    gcc --version | head -n1; \
    make -C "/usr/src/linux-headers-${KABI}-${KFLAVOUR}" M=/build modules; \
    modinfo /build/dummy_hcd.ko

########################################################################################
# kernel: Ubuntu's image and modules; computes the module closure for the guest.
FROM ${UBUNTU} AS kernel
ARG KABI
ARG KFLAVOUR
ARG MODULES
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        "linux-image-${KABI}-${KFLAVOUR}" "linux-modules-${KABI}-${KFLAVOUR}" kmod \
        python3-minimal zstd; \
    rm -rf /var/lib/apt/lists/*
COPY extract-image.py /usr/local/bin/extract-image.py
COPY --from=dummy-hcd /build/dummy_hcd.ko /usr/lib/modules/${KABI}-${KFLAVOUR}/updates/dummy_hcd.ko
RUN set -eux; \
    k="${KABI}-${KFLAVOUR}"; \
    depmod -a "$k"; \
    ours="$(modinfo -k "$k" -F vermagic dummy_hcd)"; \
    theirs="$(modinfo -k "$k" -F vermagic uhid)"; \
    test "$ours" = "$theirs"; \
    mkdir -p /out/modules; \
    for m in ${MODULES}; do modprobe -S "$k" --show-depends "$m"; done \
        | awk '$1 == "insmod" { print $2 }' | xargs -n1 readlink -f | sort -u > /out/modules.list; \
    while read -r f; do \
        mkdir -p "/out/modules$(dirname "$f")"; cp -a "$f" "/out/modules$f"; \
    done < /out/modules.list; \
    for f in modules.builtin modules.builtin.modinfo modules.order; do \
        cp -a "/usr/lib/modules/$k/$f" "/out/modules/usr/lib/modules/$k/"; \
    done; \
    python3 /usr/local/bin/extract-image.py /boot/vmlinuz-"$k" /out/Image; \
    cp /boot/config-"$k" /out/config; \
    echo "$k" > /out/kernel-release; \
    cat /out/modules.list

########################################################################################
# guest: the userland the tests run in, plus the trimmed modules.
#
# vsmartcard-vpcd is the vpcd IFD handler for pcscd (tests/vpcd.sh, crates/lk-vpcd): the
# package installs the driver and a reader.conf entry, so every pcscd started in the guest
# loads it and shows two "Virtual PCD" slots, listening for a card on TCP 35963 and 35964
# (0x8C7B + slot). The check after the install fails the build if that entry or its driver
# is missing or names another port. The tests change FRIENDLYNAME themselves where a client
# needs it (ykman: see tests/vpcd.sh), so the image keeps the package's file as shipped.
# python3-pyscard (a dependency of yubikey-manager) is named because tests use it directly.
FROM ${UBUNTU} AS guest
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        python3 python3-fido2 fido2-tools \
        pcscd libccid pcsc-tools opensc yubikey-manager python3-pyscard vsmartcard-vpcd \
        gnupg scdaemon \
        usbutils kmod udev procps evtest busybox-static strace; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log \
        /usr/share/doc/* /usr/share/man/* /usr/share/info/* /usr/share/locale/* \
        /usr/share/lintian /usr/share/bash-completion /usr/share/zsh
RUN set -eux; \
    conf=/etc/reader.conf.d/vpcd; \
    cat "$conf"; \
    grep -q -E '^DEVICENAME[[:space:]]+/dev/null:0x8C7B[[:space:]]*$' "$conf"; \
    lib="$(sed -n 's/^LIBPATH[[:space:]]*//p' "$conf")"; \
    test -f "$lib"; \
    ls -l "$lib"; \
    dpkg-query -W vsmartcard-vpcd pcscd
COPY --from=kernel /out/modules/ /
RUN set -eux; \
    k="$(ls /usr/lib/modules)"; \
    depmod -a "$k"; \
    modinfo -k "$k" -F filename uhid dummy_hcd libcomposite usb_f_fs usbhid hid_generic usbmon

########################################################################################
# pack: the guest tree as one cpio archive (ownership and modes as in the guest stage).
FROM ${UBUNTU} AS pack
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends cpio; \
    rm -rf /var/lib/apt/lists/*
COPY --from=guest / /guestroot/
COPY --from=kernel /out/Image /out/config /out/kernel-release /out/modules.list /out/
RUN set -eux; \
    cd /guestroot; \
    rm -rf boot/* dev/* proc/* sys/* run/* tmp/* .dockerenv etc/resolv.conf etc/hostname; \
    du -sh --apparent-size . | tee /out/rootfs-size; \
    find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -6 > /out/base.cpio.gz; \
    ls -l /out

########################################################################################
# final: QEMU and the artifacts. tools/linux-guest/guest-run.sh runs in this image.
FROM ${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends qemu-system-arm cpio; \
    rm -rf /var/lib/apt/lists/*
COPY --from=pack /out/ /opt/localkey-guest/
