# Manual testing against KeePassXC

The automated tests use a fake KeePassXC and cover the wire protocol. KeePassXC's own behavior (error codes, dialogs, matching) is checked by hand against a live instance, using the files in [tests/manual/](../tests/manual). **Nothing there is a real secret.**

## Files

- `tests/manual/database.xml`: the definition of the test database, as a KeePassXC XML export. It is tracked in git. `database.kdbx` is generated from it and not tracked. Run `mise run database:import` (needs `keepassxc-cli`) to create it, or to rebuild it, which overwrites an existing file.
- `tests/manual/database.kdbx` (generated): the test database, with the master password `password`. Every entry has its `kgrant://` URL as an *additional URL* and an empty main URL, the same way real entries are set up.
  - `Multi-Field`: `kgrant://multi-field`, with the fields `KPH: Multi-Field Custom` (two lines, `line one` and `line two`), `KPH: Username` = `{USERNAME}` and `KPH: Password` = `{PASSWORD}`. The last two are how real entries expose their username and password. KeePassXC resolves the placeholders, so `kgrant` gets `standard-username` and `standard-password`, the values of the standard fields. The plain attribute `Multi-Field Custom` has no prefix and must not be returned.
  - `Default`: `kgrant://default`, `KPH: Value` = `default`, and an attribute `Email` without the prefix. Used for the deny case.
  - `Duplicate 1` and `Duplicate 2`: both `kgrant://duplicate`, `KPH: Value` = `duplicate-1` and `duplicate-2`.
  - `No Fields`: `kgrant://no-fields`, no `KPH: ` field, only a password.
  - `Mixed Case & Symbols`: `kgrant://mixed-case-symbols`, `KPH: Value` = `sanitized`. The name has to be turned into that URL.
  - Contains the pairing named `test` (custom data `KPXC_BROWSER_test`).
- `tests/manual/association.json`: the matching client side of that pairing (`id` `test` plus the identification key). It only works with this database.

## Before you run anything

KeePassXC answers for **whichever database is active**, and locking one switches to another open database. If a real database is open too, requests can end up there. That is harmless, because the pairing is unknown to it, but still unwanted. So open `tests/manual/database.kdbx` and make it the unlocked, active database first, and never request anything from a real database. Also use a separate state directory, so your real association file is not touched:

```sh
export XDG_STATE_HOME=$(mktemp -d)
install -D -m 600 tests/manual/association.json "$XDG_STATE_HOME/kgrant/association.json"
```

`install -m 600` is needed because git doesn't store file permissions beyond the executable bit, and `kgrant` refuses an association file that others can read.

## Cases

The setting "Return also advanced string fields which start with KPH:" has to be on in KeePassXC's browser-integration settings. Each command opens a dialog in KeePassXC (unless you chose to remember the decision) and waits for your answer.

| Command | Expected |
|---|---|
| `cargo run -q -- get Multi-Field Username Password "Multi-Field Custom" --json` | one dialog, one line with the three values, the placeholders resolved: `{"Multi-Field Custom":"line one\nline two","Password":"standard-password","Username":"standard-username"}` |
| `cargo run -q -- get "multi field" Username` | the same entry (`kgrant://multi-field`): prints `standard-username` |
| `cargo run -q -- get Multi-Field "Multi-Field Custom"` | prints the two lines, as they are |
| `cargo run -q -- get Multi-Field Username Password` | error: 2 fields need --json (before KeePassXC is asked) |
| `cargo run -q -- get Multi-Field Email` | error: no field `KPH: Email`, and the fields the entry has |
| `cargo run -q -- get Default Email` | error: no field `KPH: Email` (the plain attribute `Email` is not a field), listing `Value` |
| `cargo run -q -- get "Mixed Case & Symbols" Value` | prints `sanitized` (the URL is `kgrant://mixed-case-symbols`) |
| `cargo run -q -- get Duplicate Value` | error: 2 entries share the URL `kgrant://duplicate`, with their titles, and no values |
| `cargo run -q -- get "No Fields" Value` | error: no field, with the hint at the setting (and never `only-a-password`) |
| `cargo run -q -- get Nope Value` | error: no entry has the URL `kgrant://nope` |
| `get Default Value`, click *Deny* in the dialog | error: access was denied (or not accessible) |
| `get Default Value` with the setting off | the hint at the setting |
| `get Default Value` with `database.kdbx` locked and no other database open | error: KeePassXC is locked |
| `get Default Value` with another, unlocked database active | error: the active database is not paired |
| `get Default Value` with KeePassXC closed | error: KeePassXC is not running |
| `get Default Value` with `XDG_STATE_HOME` empty (no association file) | error: not paired yet, run `kgrant pair` |

The locked, other-database and closed cases change the state of your KeePassXC, so set them up deliberately.

## Pairing from scratch

Skip the `install` line, make `tests/manual/database.kdbx` active and run `cargo run -q -- pair`. Approve the pairing and name the connection in KeePassXC's dialog. Then copy the new `$XDG_STATE_HOME/kgrant/association.json` to `tests/manual/association.json` and re-export the definition with `mise run database:export`. Both the definition and `association.json` change, so commit them together.
