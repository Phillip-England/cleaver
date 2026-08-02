# Cleaver

Cleaver is a small web app for encrypting and decrypting files in the browser. A single Go binary serves the bundled UI assets from `public/`, so the app can be copied and run without a separate static file directory.

## How It Works

1. Open Cleaver in a browser.
2. Choose a file on the Encrypt page.
3. Enter a numeric PIN.
4. Download the encrypted `.lock` file, all ten shard files, and the recovery note.
5. To decrypt, choose the `.lock` file, enter the same PIN, and provide the shard files.

Cleaver cannot recover a lost PIN, missing shard file, or corrupted lock file.

## Build

```sh
go test ./...
go build -o cleaver .
```

The binary includes the contents of `public/` through Go embed.

## Run

```sh
./cleaver
```

By default, Cleaver listens on `0.0.0.0:5544`, which is suitable for a container or server behind a reverse proxy.

To expose a different address:

```sh
./cleaver -addr 127.0.0.1:5544
```
