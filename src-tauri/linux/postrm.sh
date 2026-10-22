#!/bin/sh
# BirdoVPN .deb post-removal script: dpkg runs it as root after removing the
# package's files (tauri.conf.json, bundle.linux.deb.postRemoveScript).
#
# MR-654 (owner decision 2026-10-07): `apt purge` / `dpkg --purge` deletes
# the application data BirdoVPN kept for root, which is who runs it (the
# client needs root, and pkexec gives it root's home): the ML-KEM keypair and
# the device id (~/.config/BirdoVPN), settings.json, its key file and the
# consent record (~/.config/uk.birdo.vpn.desktop), the log and the app's
# other records (~/.local/share/BirdoVPN), the crash reports
# (~/.local/share/Birdo VPN) and the WebView's folders. A plain `apt remove`
# keeps them, as Debian keeps a removed package's configuration, and so does
# an upgrade.
#
# The same folders as the app's own `--remove-leftovers-and-exit
# --with-app-data` (src/utils/app_data_removal.rs, whose test pins this
# list), which this script cannot run: dpkg has deleted the app by now.
# Not reachable from here, and so not removed: a home other than root's (a
# launch with `sudo -E` keeps the user's) and the tokens in a Secret Service
# keyring (dpkg has no session bus). docs/UNINSTALL.md says how to remove
# those: the app's own flag, run before the purge.
#
# Never follows a link: `rm -rf` removes a link, at the top or anywhere
# below, as a link, and never enters it.
#
# Kept, as on Windows (W1-008): /var/lib/birdovpn, the DNS and route journals
# a killed session left, which a reinstall needs to put back what that
# session changed. Nothing in it is secret.
set -e

case "$1" in
    purge)
        home=$(getent passwd root | cut -d: -f6)
        [ -n "$home" ] || home=/root
        for dir in \
            "$home/.config/BirdoVPN" \
            "$home/.config/uk.birdo.vpn.desktop" \
            "$home/.local/share/BirdoVPN" \
            "$home/.local/share/Birdo VPN" \
            "$home/.local/share/uk.birdo.vpn.desktop" \
            "$home/.cache/uk.birdo.vpn.desktop"
        do
            rm -rf -- "$dir" || echo "birdovpn: could not remove $dir" >&2
        done
        ;;
esac

exit 0
