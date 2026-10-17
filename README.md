# ShieldAV

A small open-source Android antivirus app (Kotlin).

- Scans **installed apps** (hashes every APK/split) and **any folder** you pick.
- Matches against a local **hash signature database** (MD5 / SHA-256).
- Flags risky permission combinations as "review" (heuristic, not a verdict).
- Updates definitions from the app (button) and automatically every ~24 h on unmetered Wi-Fi.
- Definitions come from open sources; APK is built by GitHub Actions.

## How definitions work

The **Build definitions** workflow (every 6 h, or run manually) uses ClamAV's official
`freshclam` to fetch the ClamAV database, extracts its hash signatures (`.hdb`/`.hsb`),
optionally adds MalwareBazaar hashes, and publishes `definitions.txt.gz` to a release
named `definitions`. The app downloads
`https://github.com/<owner>/<repo>/releases/download/definitions/definitions.txt.gz`
(the repo that built it, baked in at build time).

Optional: add a free abuse.ch Auth-Key as repo secret `MB_AUTH_KEY` to include MalwareBazaar.
Check the ClamAV and abuse.ch terms of use before redistributing their data.

## Get the APK (no Android Studio needed)

1. Create a **public** GitHub repo and push this folder to `main`.
2. Repo **Settings → Actions → General**: allow workflows, and set *Workflow permissions* to **Read and write**.
3. **Actions → Build definitions → Run workflow** (creates the `definitions` release).
4. **Actions → Build APK** runs on push. Download `ShieldAV-apk` from the run, unzip, install `ShieldAV.apk`
   (allow "install unknown apps"). Push a tag like `v1.0` to also attach the APK to a GitHub Release.
5. In the app tap **Update virus definitions**, then scan.

Test: save the standard EICAR test string as `eicar.com` in a folder and scan that folder.

## Signing (optional)

Without secrets the APK is signed with the debug key (OK for personal use; updates only work
between builds with the same key). For a stable key add secrets `KEYSTORE_B64` (base64 of your
.jks), `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.

## Limitations

Hash matching only detects *exactly known* files; repackaged or new malware is missed, and
ClamAV's hash set is mostly desktop malware. It does no real-time protection. For serious
protection also keep Google Play Protect on.
