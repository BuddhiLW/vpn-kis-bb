# cljw compat layer

ClojureWasm (`cljw`) has no JVM, so the few third-party namespaces
vpn-kis-bb uses under Babashka are re-implemented here with the same
names and the same semantics, on top of what cljw ships
(`clojure.java.shell`, `java.io.File`, `clojure.data.json`, futures).

This directory is **mounted ahead of `src/` on the cljw classpath only**:

    cljw -cp cljw:src -m vpn-kis-bb.cli.main ...
    cljw build -m vpn-kis-bb.cli.main -cp cljw:src -o build/vpn-kis   # bin/build-native

Run both from a directory without a `deps.edn` (the scripts `cd /`): cljw
reads the working directory's `deps.edn`, and vpn-kis-bb's lists the
Babashka dependencies.

Under Babashka the real libraries from `bb.edn` are used and this
directory is never on the classpath, so the application code in `src/`
is identical on both runtimes (the zk-dual-runtime pattern).

| shim                        | stands in for                  | surface kept           |
|-----------------------------|--------------------------------|------------------------|
| `hive-dsl.result`           | hive-dsl v0.5.1                | ok, err, ok?, err?, bind |
| `hive-system.protocols`     | hive-system (IShell only)      | shell-exec!, shell-env, shell-which |
| `hive-system.shell.core`    | ProcessBuilder shell           | make-shell (`:in` works here only: the bb shell ignores it, so application code feeds stdin through `sh -c 'printf %s "$1" \| cmd' sh DATA`) |
| `hive-weave.safe`           | hive-weave                     | safe-future-call       |
| `hive-weave.parallel`       | hive-weave                     | bounded-pmap           |
| `babashka.fs`               | babashka/fs (subset)           | see ns docstring; `move` shells out to `mv -f` (cljw has no `File.renameTo`); `glob` is regex-free |
| `cheshire.core`             | cheshire (via clojure.data.json) | parse-string, generate-string |

Regex operations that return vectors (split, split-lines, capture groups)
are intermittently corrupted on cljw 1.14.11, so the shims avoid regex and
`src/` goes through `vpn-kis-bb.domain.re`.
