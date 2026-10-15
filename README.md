# termux-fctl

Minimal Frida controller that builds and runs on Termux (`android/arm64`),
written in C against the official `frida-core` devkit — no Python or Node
bindings required (neither ships for this platform).

## Background

Frida's scripting bindings do not publish Android-host toolchains, so the
usual `pip install frida` / `npm i frida` paths fail on Termux. What *does*
ship for `android-arm64` is `frida-core-devkit` (static lib + headers) and
`frida-gadget`. This repo contains a small controller built on exactly that.

## Build

```bash
# needs: clang, frida-core devkit unpacked at ./core
clang -DANDROID -ffunction-sections -fdata-sections -I ./core fctl.c \
  -o fctl -L ./core -lfrida-core -llog -ldl -lm -pthread -Wl,--export-dynamic
```

## Use

Target app must load `frida-gadget.so` (repack it into the APK + a
`System.loadLibrary("frida-gadget")` call) with a listen config, e.g.
`{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_load":"resume"}}`.

```bash
# list processes on the gadget, attach, load script, stream messages
./fctl script.js [pid] [output.log]
```

With no PID it attaches to the sole enumerated process. Script `send()`
payloads print to stdout and append to the output file when given.

## Limits

- Gadget side must be reachable (same device `127.0.0.1:27042` works).
- The controller only speaks to already-listening gadgets; it does not spawn,
  inject, or sign anything — use your platform's install tooling for that.
- Verified against frida-core 17.x devkit on Termux; newer ABIs may need
  small signature updates (see `frida-core.h`).

Independent community project. Not affiliated with the Frida authors
(Ole André Vadla Ravnås / Frida contributors).
