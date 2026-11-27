# Test coverage reports

CI collects line coverage from the four test suites — the protocol library,
the app, the relay, and the transparency log — and attaches the reports to
the workflow run as the `z-coverage` artifact. This note says how to read
that artifact and how to produce the same files locally.

A coverage percentage is a map of which lines the suites executed. It is
**not** a substitute for the claims in [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md): a
path can be 100% executed and still be wrong, and a path the suites do not
touch can still be specified and tested by a claim that names a different
file. Use the numbers to see where the suites do not go; use §3 of the audit
brief to see what we actually claim.

## How to read a CI report

On a GitHub Actions run of `.github/workflows/build.yml`, download the
`z-coverage` artifact. It contains:

- `summary.txt` — line coverage for each suite, and for the app a subtotal
  of `lib/core/`;
- `protocol/lcov.info`, `app/lcov.info`, `server/lcov.info`, `kt/lcov.info` —
  the same numbers in lcov form, for a local viewer (`genhtml`, IDE plugins).

The summary is also printed in the "Collect coverage reports" step's log.

If a suite in the test job did not finish, its `lcov.info` may be absent and
the summary will say `missing`. The test job still fails in that case. The
step that requires all four files runs only when the rest of the job has
succeeded.

## How to produce the same files locally

From the repository root, with Flutter 3.44.7 / Dart 3.12 and Node 22 or
newer on `PATH`. The Flutter app suite is large and is run with
`--concurrency=1`, as in CI; expect it to take the better part of an hour
and to want several gigabytes of RAM. The other three suites are shorter.

```bash
# Relay
cd server
mkdir -p coverage
node --test --experimental-test-coverage   --test-reporter=spec --test-reporter=lcov   --test-reporter-destination=stdout   --test-reporter-destination=coverage/lcov.info   test/*.test.js

# Transparency log
cd kt
mkdir -p coverage
node --test --experimental-test-coverage   --test-reporter=spec --test-reporter=lcov   --test-reporter-destination=stdout   --test-reporter-destination=coverage/lcov.info   test/*.test.js

# Protocol library
cd protocol
dart test --coverage=coverage
dart pub global activate coverage
dart pub global run coverage:format_coverage --lcov   --in=coverage --out=coverage/lcov.info --report-on=lib --package=.

# App (writes app/coverage/lcov.info)
cd app
flutter test --concurrency=1 --coverage
```

To print the same summary CI attaches:

```bash
mkdir -p coverage-out/protocol coverage-out/app coverage-out/server coverage-out/kt
cp protocol/coverage/lcov.info coverage-out/protocol/lcov.info
cp app/coverage/lcov.info     coverage-out/app/lcov.info
cp server/coverage/lcov.info  coverage-out/server/lcov.info
cp kt/coverage/lcov.info      coverage-out/kt/lcov.info
python3 tool/coverage_summary.py --dir coverage-out --require protocol,app,server,kt
```

`coverage/` directories are gitignored. Nothing in this document changes
which tests run, or their pass/fail rules.
