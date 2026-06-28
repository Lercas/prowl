# Mobile App Scanning

```
prowl mobile <target>
```

Unpack and scan an Android **APK** or iOS **IPA** for secrets baked into the app. The `<target>` is an `.apk`/`.ipa` file, a local path, or an `https://` URL:

```bash
prowl mobile app-release.apk
prowl mobile MyApp.ipa
prowl mobile https://example.com/builds/app-release.apk
```

An APK/IPA is just a ZIP archive, so prowl walks **every entry** and scans it. This is **pure Go — no Android SDK, no `apktool`, no Xcode required.** When `<target>` is a URL, the artifact is downloaded through the SSRF-guarded HTTP client into a temp directory before scanning.

> To scan a container image, see [Container Scanning](Container-Scanning.md); to scan a remote repo, see [Repository Scanning](Repository-Scanning.md).

`prowl mobile` accepts every [`prowl scan`](Scanning-Files.md) flag — `--ml`, `--verify`, `--format`, `--max-size`, and the rest — plus the two strings flags below. See [Scanning Files](Scanning-Files.md) for the full flag reference; the notes here cover only what is specific to mobile artifacts.

## What gets scanned

prowl walks every entry in the archive and handles it by kind:

### Text resources, scanned raw

Resource files, JSON, plist, and XML entries are scanned as raw text. This is where most secrets live, including two **high-value** files prowl pays special attention to:

- `google-services.json` (Android) and `GoogleService-Info.plist` (iOS) — these routinely leak **Google API keys** and **project ids**, and are a classic source of live Firebase/Maps credentials.

### Binary entries, scanned via printable-strings

Binary entries — `.dex` bytecode, `resources.arsc`, `.so` native libs, and Mach-O binaries — get a pure-Go **printable-strings pass** before scanning, so keys baked into a binary's string tables still surface. The strings extractor recognizes both:

- **8-bit ASCII** runs, and
- **UTF-16LE** runs,

then feeds the recovered strings into the detector. A key compiled into a `.dex` string table or a native `.so` is caught even though the file is not text.

## Flags

These two flags control the strings pass; everything else is a standard [`prowl scan`](Scanning-Files.md) flag.

| Flag | Effect |
|------|--------|
| `--no-strings` | Disable the printable-strings pass on binary entries. Only the raw text resources are scanned. |
| `--min-run N` | Minimum run length (in characters) for an extracted string to be kept. Shorter runs are discarded as noise. |

All standard scan flags apply unchanged: `--ml`, `--verify`, `--verified-only`, `--format pretty|json|sarif`, `-o`/`--output`, `--fail-on <level>`, `--max-size`, `--rules-dir`, `--tags`, `--baseline`, and the rest.

## Examples

```bash
# Scan an Android build, run the ML false-positive filter
prowl mobile app-release.apk --ml

# Scan an iOS build, confirm hits are live against the provider
prowl mobile MyApp.ipa --verify

# Download a build over HTTPS (SSRF-guarded) and scan it
prowl mobile https://example.com/builds/app-release.apk

# Skip the binary strings pass — only scan text resources
prowl mobile app-release.apk --no-strings

# Keep only longer extracted strings, machine-readable report
prowl mobile app-release.apk --min-run 12 --format json -o mobile.json
```

## See also

- [Container Scanning](Container-Scanning.md) — pull & scan an OCI/Docker image
- [Scanning Files](Scanning-Files.md) — the filesystem scan and shared flags
- [Live Verification](Live-Verification.md) — confirm findings are live credentials
- [Rules](Rules.md) — what the detector matches
- [Security Model](Security-Model.md) — the SSRF guard and threat model
- [Home](README.md)
