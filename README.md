# Cleaver

Cleaver is a small web app for encrypting and decrypting files in the browser. A single Go binary serves the bundled UI assets from `public/`, so the app can be copied and run without a separate static file directory.

## How It Works

1. Open Cleaver in a browser.
2. Choose a file on the Encrypt page.
3. Enter a numeric PIN.
4. Download the encrypted `.lock` file and its single `.bundle` file.
5. To decrypt, choose the `.lock` file, enter the same PIN, and provide the bundle.

The bundle contains randomly ordered key records with opaque random identifiers instead of numbered shard files. CSV lock files can also be opened on the **Edit lock file** page. After the PIN and bundle are verified, export only a new `.lock` file that uses the same credentials and bundle.

Cleaver cannot recover a lost PIN, missing bundle, or corrupted lock file.

## Build

```sh
go test ./...
go build -o cleaver .
```

The binary includes the contents of `public/` through Go embed.

## Run

Initialize local configuration and SQLite storage first:

```sh
./cleaver init
```

This creates `./config/.env` and `./data/main.sqlite`. The generated env file contains a placeholder admin account:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-now
SESSION_SECRET=<generated-secret>
DB_PATH=../data/main.sqlite
```

Change `ADMIN_PASSWORD` before any real deployment.

```sh
./cleaver
```

When running Cleaver on the same computer as the browser, open
`http://localhost:5544`. Browsers allow Web Crypto on localhost.

By default, Cleaver listens on `0.0.0.0:5544`, which is suitable for a container or server behind a reverse proxy.
If you access it through a hostname or another computer, the reverse proxy must
serve Cleaver over HTTPS; browsers disable Web Crypto on insecure HTTP pages.

To expose a different address:

```sh
./cleaver -addr 127.0.0.1:5544
```

## Admin Portal

Public Cleaver pages remain available at `/`. The admin portal is available directly at `/login` and redirects protected admin routes to login when there is no valid signed session.

After login, open `/admin` to:

- upload arbitrary registry artifacts under operator-chosen names
- download or delete stored artifacts
- encrypt a source file into registry-stored lock and bundle artifacts
- choose any two stored artifacts plus a PIN to attempt unlock
- edit unlocked CSV files as a spreadsheet and relock back into the stored lock artifact

Failed admin logins are tracked in SQLite by client IP for 24 hours. Five recent failures returns HTTP 403. Failed admin unlock attempts use a separate SQLite ledger with the same 24-hour, five-failure rule.
