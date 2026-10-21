# README

## About

This is the official Wails Vue template.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

Release builds must remove local source paths. With Go and Wails v2.12.0 on PATH:

```powershell
wails build -trimpath -ldflags "-s -w -buildid="
```

Use `NHDD-cpp-modular/release/build-desktop.ps1` for the distributable ZIPs,
checksums and third-party licenses. Do not upload `wails dev` or debug builds.
The Windows GUI requires WebView2 Runtime and ADB; the Android engine still
requires Root. Advanced ART / event / spawn controls are available in the C++ CLI,
not all exposed by the desktop UI.
