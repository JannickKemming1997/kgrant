# kgrant

`kgrant` gives programs scoped, user-approved access to credentials stored in [KeePassXC](https://keepassxc.org). It talks to the running, unlocked KeePassXC over its browser-integration socket. You enter the master password once, in KeePassXC, and approve each request there.

```sh
kgrant pair                                    # pair with the open KeePassXC database (once per machine)
kgrant get AWS "Access Key ID"                 # print the field `KPH: Access Key ID` of the entry with the URL `kgrant://aws`
kgrant get AWS "Access Key ID" "Secret Access Key" --json   # several fields of one entry, with one confirmation
```

## Setup

1. In KeePassXC: *Settings → Browser Integration*, enable it (you don't need to select a browser) and turn on "Return also advanced string fields which start with 'KPH: '".
2. Run `kgrant pair` with the right database active and approve the dialog. The pairing is stored in `$XDG_STATE_HOME/kgrant/association.json` (`~/.local/state/kgrant/` by default) with mode `0600`. It works as a bearer token, so keep it out of repositories.
3. Prepare the entries you want to expose. Add the additional URL `kgrant://<entry>`, where `<entry>` is the name of the entry in kebab-case (`AWS Keys` becomes `kgrant://aws-keys`), and a custom field `KPH: <field>` for each value. The password and user name of the entry are never read. To expose them, set a `KPH:` field to `{USERNAME}` or `{PASSWORD}`.

With one field, `kgrant get` prints its value as it is. With several, you need `--json`, which prints an object from field name to value. All fields of one entry are fetched in one request, so KeePassXC asks only once per entry.

## Library

`kgrant` is also a library. Code that needs secrets takes a `&dyn Secrets`. In production that is `KeePassXc`, and in tests it can be `StaticSecrets` or any closure.

## Development

You need Rust (2024 edition) and a C linker such as `gcc`. See [docs/development.md](docs/development.md).

## Documentation

- [Design](docs/design.md): the protocol, the database convention and the security model.
- [Development](docs/development.md): code layout, checks and conventions.
- [Manual testing](docs/testing.md): trying changes against a live KeePassXC.

## License

[EUPL-1.2](LICENSE).
