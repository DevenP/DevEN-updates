# DevEN updates

Built, signed updates for the DevEN TV app. TVs with DevEN installed check this repo and update
themselves; there is nothing here to download by hand.

- `latest.json` names the current app bundle and helper with their SHA-256 checksums.
- `latest.sig` / `latest.der.sig` are its ECDSA P-256 signature. The app and helper only run an
  update whose manifest carries the release key's signature and whose files match the checksums.
- `<version>/` holds that release's files.

The source is private; this repo only holds what the TVs download.
