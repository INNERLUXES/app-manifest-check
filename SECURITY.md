# Security

## Reporting a problem

Write to info@innerluxes.dev with the subject line "app-manifest-check security", or use private vulnerability reporting on this repository. Please do not open a public issue for a vulnerability.

Include a small made-up manifest, plist, network config, build file or config file that shows the problem, what you expected and what happened. Use made-up package ids, bundle ids and host names (such as `com.example.orders` and `example.test`), and no real signing settings, keys, internal addresses or customer files.

## Scope

In scope:

- an input that makes the tool open a network connection, run a program (Gradle, Xcode, `plutil`, a shell), or evaluate anything in a build file
- an input that makes the tool read a file other than the ones named on the command line, through a resource name, a build setting, a path in a build file or an entity
- an XML file or plist that makes the reader expand an entity, read another file, or accept a DOCTYPE other than the exact plist line described in docs/method.md
- a binary plist or compiled manifest that the tool tries to decode instead of refusing
- an input that makes the tool hang, take very long, or use unbounded memory or stack, such as deep nesting, very many elements, a crafted build file or a path that is not a regular file
- text from a component name, a domain, a key or a path that breaks a Markdown table, injects a formula into a CSV report, or rewrites the terminal through control or direction characters
- an attribute or key name that changes how objects behave inside the tool
- a config file that switches a check off without the report saying so
- a risky setting that docs/method.md says is reported, in a file the tool accepts, that the report leaves out

Out of scope: what the code of the app does, the manifests that libraries add at build time, values that Gradle or Xcode compute, and the store rules themselves (docs/limits.md lists what a check of the settings files cannot see).

Read [docs/threat-model.md](docs/threat-model.md) for the rest.
