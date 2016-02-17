# Guidelines for Contributing

These guidelines are a work in progress.

This project, and your contributions to it, are governed by the [Apache License,
version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Coding Style

* Consistency trumps these style rules, but readability trumps consistency.
  * If a source file is inconsistent to begin with, consider making a cleanup
    patch.
* Spaces are preferred over tabs as a general rule, except of course in
  languages where tabs have semantic meaning (e.g. Makefiles).
* For httpd-related C code (i.e. mod_websocket and its plugins), make an effort
  to match the style used by the Apache httpd project.
* For new files in languages that have no stylistic precedent in the project, do
  your best to follow a "globally acceptable" style for that language. Use your
  best judgment.

## Committing Changes

* Add tests for functional changes, especially bug fixes!
* Commits with one logical change (add/remove functionality, fix a bug, etc.)
  are preferred to commits with multiple changes.
  * This has nothing to do with size. Large commits that do one thing are fine.
    Commits that do several things at once are not.
* Separate logical changes from stylistic and refactoring changes.
* Follow the "standard" guidelines for git commit messages:
  * Summary of 50 characters or less
  * Body wrapped at 72 characters, with longer lines only for a good reason
* Concise summaries in the imperative mood are preferred ("Remove support for
  draft 76", "Launch a separate server for tests").
* Commit bodies should provide the context for the change. Not every commit
  _needs_ a body, but most do.
* Watch for whitespace errors such as trailing spaces, mixed tabs/spaces, etc.
  * `git diff --check` can help you with this.
