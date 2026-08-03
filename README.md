# Cleaver

Cleaver is a small web app for encrypting and decrypting files in the browser. A single Go binary serves the bundled UI assets from `public/`, so the app can be copied and run without a separate static file directory.

## How It Works

1. Open Cleaver in a browser.
2. Choose a file on the Encrypt page.
3. Enter a numeric PIN.
4. Download the encrypted `.lock` file and its single `.bundle` file.
5. To decrypt, choose the `.lock` file, enter the same PIN, and provide the bundle.

The bundle contains randomly ordered key records with opaque random identifiers instead of numbered shard files. UTF-8 text lock files can also be opened on the **Edit lock file** page. Paged Markdown files are edited one titled page at a time, can have new pages appended, and are reconstructed on export. After the PIN and bundle are verified, export only a new `.lock` file that uses the same credentials and bundle.

The **Render Markdown lock** page accepts only `.lock` files whose recorded original filename ends in `.md` or `.markdown`. It unlocks the document in the browser, splits it into titled pages using the format documented in `DASHED_MARKDOWN_STYLE.md`, and sends each page's Markdown to the local Cleaver server, where Goldmark renders it in memory. The rendered HTML is returned to the page and is not stored.

The **Alphabetize Markdown** page unlocks the same kind of paged Markdown lock entirely in the browser. It requires sections beginning with single `#` headings, rejects deeper Markdown headings and content before the first heading, sorts complete sections case-insensitively within each page, and exports a replacement `.lock` file protected by the same PIN and bundle.

Cleaver cannot recover a lost PIN, missing bundle, or corrupted lock file.

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

When running Cleaver on the same computer as the browser, open
`http://localhost:5544`. Browsers allow Web Crypto on localhost.

By default, Cleaver listens on `0.0.0.0:5544`, which is suitable for a container or server behind a reverse proxy.
If you access it through a hostname or another computer, the reverse proxy must
serve Cleaver over HTTPS; browsers disable Web Crypto on insecure HTTP pages.

To expose a different address:

```sh
./cleaver -addr 127.0.0.1:5544
```
