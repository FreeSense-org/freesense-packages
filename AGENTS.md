# freesense-packages agent rules

Optional FreeSense package integrations. Release rules are in
`FreeSense-org/freesense-os-base` `docs/release-policy.md` (R1–R9).

- `main` is Development (1.2). Changes land here first.
- `RELENG_1_1` is the Stable 1.1 maintenance branch. Only fixes reach it, as
  `git cherry-pick -x` of a `main` commit through a pull request against
  `RELENG_1_1`. Never push to it directly, never force-push it.
- `v1.1.N` tags mark released commits; they are created by the Stable seal
  and never moved or deleted.
- A package change needs a PORTVERSION or PORTREVISION bump to reach installed systems.
- An Optional-Packages-only change does not justify a Stable patch on its own unless it is a security fix (R8); it ships with the next patch.
- Merge with `gh pr merge --rebase` (keeps the `dev@freesense.org` author).
- Coding style: follow `freesense/docs/coding-standards.md` in the `freesense`
  repository; a package uses the same rules (it may namespace inside its own
  directory).
