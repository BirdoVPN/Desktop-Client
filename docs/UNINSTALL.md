# Uninstalling BirdoVPN and deleting its data

Removing the app does not, by itself, remove what BirdoVPN kept for your
account on this computer. This page says how to remove that too, on every
platform. (MR-654.)

## What "the app data" is

| What | Where (macOS) | Where (Linux, BirdoVPN run as root) |
|---|---|---|
| Sign-in tokens, the settings key, the biometric flag | Keychain, service `BirdoVPN` | Secret Service keyring, service `BirdoVPN` |
| The post-quantum (ML-KEM) key and the device id | `~/Library/Application Support/BirdoVPN` | `/root/.config/BirdoVPN` |
| Settings, their key file, the consent record | `~/Library/Application Support/uk.birdo.vpn.desktop` | `/root/.config/uk.birdo.vpn.desktop` |
| The diagnostic log | `~/Library/Application Support/BirdoVPN/logs` | `/root/.local/share/BirdoVPN/logs` |
| Crash reports | `~/Library/Application Support/Birdo VPN/crashes` | `/root/.local/share/Birdo VPN/crashes` |
| The app window's storage and cache | `~/Library/WebKit/uk.birdo.vpn.desktop`, `~/Library/Caches/uk.birdo.vpn.desktop` | `/root/.local/share/uk.birdo.vpn.desktop`, `/root/.cache/uk.birdo.vpn.desktop` |

On macOS, `~` is the home folder BirdoVPN was started with (with `sudo`,
usually yours). On Linux the folders are root's when BirdoVPN is started with
`pkexec`, and your own when it is started with `sudo -E`.

**Kept on purpose:** `/var/lib/birdovpn` (Linux) and `/var/db/birdovpn`
(macOS). They hold the record of the network settings a session changed (DNS,
routes), which a reinstall uses to put back what a session that was killed
could not. Nothing in them is secret; delete them by hand if you do not plan
to reinstall.

The cleanup never follows a link: a link in one of these folders is removed
as a link, and what it points to is left alone.

## Before you start

Disconnect and quit BirdoVPN. Signing out first also deletes the sign-in
tokens from the keychain, wherever the cleanup below cannot reach them.

## Windows

Uninstall from Settings > Apps and tick **Delete the application data** in the
uninstaller.

## Linux (.deb)

```sh
sudo apt purge birdo-vpn
```

`apt purge` deletes the folders above for root. A plain `apt remove` keeps
them, as Debian keeps a removed package's configuration; an upgrade keeps them
too.

Two things the purge cannot reach, because the package manager runs without
your desktop session: the tokens in a Secret Service keyring, and the folders
of a BirdoVPN started with `sudo -E` (they are in your home, not root's). To
remove those as well, run this **before** `apt purge`, the same way you start
BirdoVPN:

```sh
sudo -E birdo-vpn-desktop --remove-leftovers-and-exit --with-app-data
```

## Linux (an AppImage from 1.4.50 or earlier)

BirdoVPN no longer ships an AppImage (owner decision 2026-10-28; 1.4.50 was the
last): Linux ships the .deb only. An AppImage you still have has no
uninstaller. Run it once with the cleanup flags, the same way you start it,
then delete the file:

```sh
sudo ./BirdoVPN_*.AppImage --remove-leftovers-and-exit --with-app-data
rm ./BirdoVPN_*.AppImage
```

## macOS

Run the app's cleanup the same way you start BirdoVPN (with `sudo`), then move
the app to the Bin:

```sh
sudo /Applications/BirdoVPN.app/Contents/MacOS/birdo-vpn-desktop --remove-leftovers-and-exit --with-app-data
```

## What the cleanup prints

```
--remove-leftovers-and-exit --with-app-data: removed 4 folder(s) and 2 keystore entr(ies); 0 failed
```

Anything it could not remove is listed above that line, with the reason (for
example a keychain it could not reach). It deletes nothing else, and it does
not start the app.
