package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

const defaultAddr = "0.0.0.0:5544"

//go:embed public
var publicFiles embed.FS

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cleaver:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("cleaver", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", defaultAddr, "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("usage: cleaver [-addr 0.0.0.0:5544]")
	}

	handler, err := staticHandler()
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "cleaver running at %s\n", browserURL(*addr))
	return http.ListenAndServe(*addr, handler)
}

func browserURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func staticHandler() (http.Handler, error) {
	root, err := fs.Sub(publicFiles, "public")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(root))
	markdown := goldmark.New(goldmark.WithExtensions(extension.GFM))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/render" {
			renderMarkdown(w, r, markdown)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		if _, err := fs.Stat(root, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	}), nil
}

const maxMarkdownBytes = 2 << 20

func renderMarkdown(w http.ResponseWriter, r *http.Request, markdown goldmark.Markdown) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMarkdownBytes)
	source, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "markdown is too large", http.StatusRequestEntityTooLarge)
		return
	}

	var rendered strings.Builder
	if err := markdown.Convert(source, &rendered); err != nil {
		http.Error(w, "could not render markdown", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, rendered.String())
}
