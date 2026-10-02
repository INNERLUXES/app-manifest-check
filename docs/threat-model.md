# Threat model

## What the tool touches

- It reads the files named with `--android`, `--network-config`, `--gradle`, `--ios`, `--entitlements` and `--config`, and nothing else. It does not follow a path, a resource name or an address written inside them, and it does not look at the folders around them.
- It writes only to the screen (standard output and standard error).
- It opens no network connection and runs no program: not Gradle, not Xcode, not `plutil`, not a shell.

## What the input may hold

The settings files of an app are often checked in a pipeline that runs on pull requests, including pull requests from people outside the team, and a review of an app may start from files sent by a client or a vendor. The tool treats every file as possibly hostile. Any XML file can hold a DOCTYPE with entity declarations meant to expand into gigabytes of text or to read another file or a network address, very deep nesting, very many elements, or attribute names meant to reach an object's prototype. A plist can hold a DOCTYPE that looks like Apple's line but adds an internal subset, or be a binary plist made to confuse a reader. A build file is a program that Gradle would run: it can download plugins, run commands and read the disk. Names of components, permissions, domains and keys can hold control characters, direction characters, or text meant for a spreadsheet or a Markdown table. A config file can try to switch checks off.

## What could go wrong, and what stops it

| Risk | Control |
| --- | --- |
| A build file runs code on the machine that checks it (a plugin, a task, a `providers.exec` call) | The tool never runs Gradle and never evaluates the file; it is read as text and searched with anchored patterns. There is no code path that starts a process |
| A DOCTYPE defines entities that expand exponentially (a "billion laughs" file) or an external entity that reads a local file or a network address | The XML reader refuses any DOCTYPE or ENTITY declaration before it reads what is inside, and refuses every entity except the five that XML predefines. The one plist DOCTYPE line Xcode writes is matched exactly, with no internal subset, and skipped as text; the DTD it names is never opened |
| A crafted binary plist or a compiled manifest exploits a binary parser | There is no binary parser: both are recognised by their first bytes and refused, with the command or file to give instead |
| A huge file, deeply nested XML or very many elements exhaust memory or time | Files over 10 MB are refused from the size of the open file before it is read; XML deeper than 64 levels or with more than 200,000 elements is refused. The XML reader keeps its own stack instead of recursing on the input; the plist reader recurses only as deep as the XML reader allows. Every pattern is anchored and free of nested repetition |
| A path that is not a regular file (a folder, a device, a pipe) makes the tool hang or read without end | The size and type are taken from the open file, and anything that is not a regular file is refused |
| An attribute or key named `__proto__` or `constructor` changes how objects behave | Attributes and dict keys are kept in objects without a prototype; tests check that no prototype changes |
| A malformed file is read differently from Android or iOS, so a risky setting is missed | Anything that is not well-formed XML, a plist key given twice, or a plist value of an unknown type is refused with its line, and the run stops with exit code 2; nothing is guessed |
| A component name, domain or key rewrites the terminal through escape sequences, or reorders text with direction characters | Control characters (C0 and C1), line and paragraph separators and Unicode direction controls are replaced by a space before any text reaches a report or an error message, and the length is capped |
| A name breaks the Markdown table in the job summary, or hides text as an HTML tag | Pipes, backslashes, line breaks, `<`, `>` and `&` are escaped in every table cell |
| A CSV report runs a formula when opened in a spreadsheet | Cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`; every cell is quoted as RFC 4180 says |
| A config file quietly switches a check off through a typo, or an allow list that matches far more than intended | Every key is checked and an unknown key or an unknown check stops the run. Domain entries are host names, with `*.` only as a leading label; wildcards in ignore subjects are matched without building a regular expression from the input. The report counts the findings that were left out |
| A file argument names a URL, so the tool becomes a fetcher | Arguments that look like addresses are refused; the tool has no code that opens a connection |

## Out of scope

What the code of the app does, the manifests that libraries add at build time, values that Gradle or Xcode compute, and the security of the store build itself. docs/limits.md lists what a check of the settings files cannot see.
