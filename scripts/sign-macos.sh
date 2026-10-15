#!/usr/bin/env bash
# Developer ID signs and notarizes the two macOS release binaries. Run by the
# macos-sign job of .github/workflows/release.yaml on a GitHub hosted Mac in
# the macos-release environment. It builds nothing: the binaries come from the
# macos-build job, which has no secrets, so no build script of a dependency
# ever runs next to the signing identity.
#
#   scripts/sign-macos.sh --bin-dir <dir> --notary-dir <dir>
#
# For <bin-dir>/aarch64-apple-darwin/fabric and
# <bin-dir>/x86_64-apple-darwin/fabric, already stripped (strip before signing,
# never after), it:
# - signs with the hardened runtime, a secure timestamp and the identifier
#   com.affinidi.trust-fabric-cli
# - checks the signature with `codesign -vvv --strict`, `codesign -dvv` and
#   the designated requirement below
# - notarizes with `notarytool submit --wait`, keeping the submission and
#   Apple's log in <notary-dir>
# - asks Gatekeeper with `spctl --assess`, which must report a notarized
#   Developer ID
# A bare binary can't be stapled, so Gatekeeper looks the ticket up online.
# It never runs the binaries: the workflow does that in a later step, once the
# secrets and the keychain are gone.
#
# CLI_MACOS_TEAM_ID is Affinidi's 10-character Team ID. It isn't a secret and
# is set in the workflow. The secrets, all from the macos-release environment:
#   APPLE_SIGNING_IDENTITY            Developer ID Application: <name> (<Team ID>)
#   APPLE_DEVELOPER_ID_P12            base64 of the .p12 holding the certificate and its key
#   APPLE_DEVELOPER_ID_P12_PASSWORD   the .p12 password
#   APPLE_NOTARY_KEY                  the App Store Connect API key, the text of the .p8 file
#   APPLE_NOTARY_KEY_ID               its 10-character Key ID
#   APPLE_NOTARY_ISSUER_ID            the team's Issuer ID, a lower-case UUID
# The .p12 and the .p8 are written to a private temporary folder and removed,
# with the throwaway keychain, when the script exits. No secret is printed.
#
# Everything up to the macOS check needs no Mac, so
# scripts/test-release-scripts.sh runs those checks on any machine.
set -euo pipefail

identifier="com.affinidi.trust-fabric-cli"
targets="aarch64-apple-darwin x86_64-apple-darwin"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
  echo "error: $*" >&2
  exit 1
}

note() {
  echo "$*" >&2
}

usage() {
  echo "usage: $0 --bin-dir <dir> --notary-dir <dir>" >&2
  exit 2
}

bin_dir=""
notary_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin-dir | --notary-dir)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --bin-dir) bin_dir="$2" ;;
        --notary-dir) notary_dir="$2" ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done
if [ -z "${bin_dir}" ] || [ -z "${notary_dir}" ]; then
  usage
fi
[ -d "${bin_dir}" ] || die "--bin-dir ${bin_dir} is not a directory"

for name in CLI_MACOS_TEAM_ID APPLE_SIGNING_IDENTITY APPLE_DEVELOPER_ID_P12 APPLE_DEVELOPER_ID_P12_PASSWORD \
  APPLE_NOTARY_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID; do
  [ -n "${!name:-}" ] || die "${name} is not set (see the macOS signing part of CONTRIBUTING.md)"
done
if ! [[ "${CLI_MACOS_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]]; then
  die "CLI_MACOS_TEAM_ID is not a 10-character Team ID"
fi
case "${APPLE_SIGNING_IDENTITY}" in
  "Developer ID Application: "*" (${CLI_MACOS_TEAM_ID})") ;;
  *) die "APPLE_SIGNING_IDENTITY is not a Developer ID Application identity of Team ${CLI_MACOS_TEAM_ID}" ;;
esac
# The values are checked by shape only, before anything is signed. Whether
# Apple takes them is asked further down. Secrets go through pipes, never
# here-strings, which bash 3.2 writes to a temporary file. grep reads all of
# its input, so printf never hits a closed pipe.
if printf '%s' "${APPLE_DEVELOPER_ID_P12}" | LC_ALL=C grep '[^A-Za-z0-9+/=[:space:]]' > /dev/null; then
  die "APPLE_DEVELOPER_ID_P12 is not base64 text (base64 -i developer-id.p12)"
fi
if ! printf '%s\n' "${APPLE_NOTARY_KEY}" | grep -x -- '-----BEGIN PRIVATE KEY-----' > /dev/null; then
  die "APPLE_NOTARY_KEY is not the text of an App Store Connect API key (.p8)"
fi
if ! [[ "${APPLE_NOTARY_KEY_ID}" =~ ^[A-Z0-9]{10}$ ]]; then
  die "APPLE_NOTARY_KEY_ID is not a 10-character Key ID"
fi
if ! [[ "${APPLE_NOTARY_ISSUER_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  die "APPLE_NOTARY_ISSUER_ID is not an Issuer ID (a lower-case UUID)"
fi

[ "$(uname -s)" = "Darwin" ] || die "macOS binaries are signed on macOS"
for tool in codesign security ditto xcrun spctl shasum; do
  command -v "${tool}" > /dev/null 2>&1 || die "${tool} is missing"
done
for target in ${targets}; do
  [ -f "${bin_dir}/${target}/fabric" ] || die "${bin_dir}/${target}/fabric is missing (a release signs both macOS binaries)"
done
mkdir -p "${notary_dir}"

work=""
keychain=""
old_default=""
cleanup() {
  if [ -n "${old_default}" ]; then
    security default-keychain -d user -s "${old_default}" > /dev/null 2>&1 || true
  fi
  if [ -n "${keychain}" ]; then
    security delete-keychain "${keychain}" > /dev/null 2>&1 || true
  fi
  if [ -n "${work}" ]; then
    rm -rf "${work}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work="$(mktemp -d "${TMPDIR:-/tmp}/fabric-sign-macos.XXXXXX")" || die "could not make a temporary folder"
old_default="$(security default-keychain -d user | sed 's/^ *"//; s/" *$//')" || die "could not read the default keychain"
keychain="${work}/fabric-signing.keychain-db"

# The secrets as files, readable by this user only.
p12="${work}/developer-id.p12"
notary_key="${work}/notary-key.p8"
(
  umask 077
  printf '%s' "${APPLE_DEVELOPER_ID_P12}" | base64 --decode > "${p12}"
  printf '%s\n' "${APPLE_NOTARY_KEY}" > "${notary_key}"
) || die "APPLE_DEVELOPER_ID_P12 is not base64 of a .p12"
notary_auth=(--key "${notary_key}" --key-id "${APPLE_NOTARY_KEY_ID}" --issuer "${APPLE_NOTARY_ISSUER_ID}")

# A keychain of its own for this run, deleted at exit.
keychain_password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
security create-keychain -p "${keychain_password}" "${keychain}" || die "could not create the signing keychain"
security set-keychain-settings -lut 3600 "${keychain}" || die "could not set the signing keychain's timeout"
security unlock-keychain -p "${keychain_password}" "${keychain}" || die "could not unlock the signing keychain"

# Apple's Developer ID intermediate (G2), which issues the Developer ID
# Application certificate, and the Apple Root CA above it. macOS ships only
# the root, so a runner without Xcode's copy of the intermediate finds "0
# valid identities", and codesign, given this keychain, builds the whole chain
# from it, root included. Both are public, from
# https://www.apple.com/certificateauthority/, and pinned by their SHA-256.
# The intermediate is valid until 2031-09-17, the root until 2035-02-09.
for cert in DeveloperIDG2CA.cer:f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a \
  AppleRootCA.cer:b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024; do
  file="${here}/apple/${cert%%:*}"
  [ -f "${file}" ] || die "${file} is missing"
  [ "$(shasum -a 256 "${file}" | awk '{ print $1 }')" = "${cert#*:}" ] ||
    die "${file} is not Apple's certificate (its SHA-256 differs)"
  security import "${file}" -k "${keychain}" > /dev/null || die "could not import ${file}"
done
security import "${p12}" -k "${keychain}" -P "${APPLE_DEVELOPER_ID_P12_PASSWORD}" -T /usr/bin/codesign > /dev/null ||
  die "could not import the .p12 (APPLE_DEVELOPER_ID_P12 or APPLE_DEVELOPER_ID_P12_PASSWORD is wrong, or the .p12 came from OpenSSL 3 without -legacy; export it from Keychain Access instead)"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${keychain_password}" "${keychain}" > /dev/null ||
  die "could not let codesign use the key"
existing_keychains="$(security list-keychains -d user | sed 's/^ *"//; s/" *$//')" ||
  die "could not read the keychain search list"
# shellcheck disable=SC2086 # one keychain path per line, none with spaces on the runner
security list-keychains -d user -s "${keychain}" ${existing_keychains} || die "could not add the signing keychain"
# Without a login session, trustd and securityd may read only the default
# keychain and the System keychain, not the search list, so codesign could
# neither build the chain nor use the key.
security default-keychain -d user -s "${keychain}" || die "could not make the signing keychain the default"
# On CI, a throwaway machine with passwordless sudo, the intermediate also
# goes into the System keychain, which trustd always reads. Never on a laptop.
if [ -n "${CI:-}" ] && sudo -n true 2> /dev/null; then
  sudo -n security add-certificates -k /Library/Keychains/System.keychain "${here}/apple/DeveloperIDG2CA.cer" > /dev/null 2>&1 ||
    note "the System keychain refused the intermediate certificate, which may already be there"
fi

# Why codesign failed, when it does. Names, hashes and trust results only.
sign_diagnostics() {
  note "keychain search list:"
  security list-keychains -d user >&2
  note "default keychain:"
  security default-keychain -d user >&2
  note "valid code signing identities in all keychains:"
  security find-identity -v -p codesigning >&2
  if security find-certificate -c "${APPLE_SIGNING_IDENTITY}" -p "${keychain}" > "${work}/identity.pem" 2> /dev/null; then
    note "trust of the identity's certificate for code signing:"
    security verify-cert -c "${work}/identity.pem" -p codeSign -k "${keychain}" >&2 || true
    note "the same, with the signing keychain only and no network:"
    security verify-cert -c "${work}/identity.pem" -p codeSign -k "${keychain}" -L -n >&2 || true
  fi
}

# The .p12 must hold the identity named, with its key. On a miss, list what
# the keychain holds and why macOS refuses each one it does:
# CSSMERR_TP_NOT_TRUSTED is a missing intermediate, CSSMERR_TP_CERT_EXPIRED an
# expired certificate, and no line at all a certificate without its key.
if ! security find-identity -v -p codesigning "${keychain}" | grep -qF "\"${APPLE_SIGNING_IDENTITY}\""; then
  note "valid code signing identities in the .p12:"
  security find-identity -v -p codesigning "${keychain}" >&2 || true
  note "every identity there, with why macOS refuses each one it does:"
  security find-identity -p codesigning "${keychain}" >&2 || true
  note "certificates there (an identity also needs its private key):"
  security find-certificate -a "${keychain}" 2> /dev/null | grep -E '"labl"|"alis"' >&2 || true
  die "the .p12 holds no valid identity \"${APPLE_SIGNING_IDENTITY}\", see the lists above"
fi

# The notary key must work before anything is signed. This only reads.
xcrun notarytool history "${notary_auth[@]}" --output-format json > /dev/null ||
  die "Apple refuses the notary key: APPLE_NOTARY_KEY, APPLE_NOTARY_KEY_ID and APPLE_NOTARY_ISSUER_ID don't belong together"

# What every release binary must meet: Apple's chain, a Developer ID
# Application certificate (the two Developer ID markers), this identifier and
# Affinidi's Team ID.
requirement="=anchor apple generic and identifier \"${identifier}\" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"${CLI_MACOS_TEAM_ID}\""

for target in ${targets}; do
  bin="${bin_dir}/${target}/fabric"
  # Unlocked again right before use, because notarizing the previous binary
  # can take a while.
  security unlock-keychain -p "${keychain_password}" "${keychain}" || die "could not unlock the signing keychain"
  if ! codesign -s "${APPLE_SIGNING_IDENTITY}" --keychain "${keychain}" -f --timestamp -o runtime -i "${identifier}" "${bin}"; then
    sign_diagnostics
    die "codesign failed for ${target}, see the diagnostics above"
  fi
  codesign -vvv --strict "${bin}" || die "codesign -vvv --strict rejects ${target}"
  details="$(codesign -dvv "${bin}" 2>&1)" || die "codesign -dvv failed for ${target}"
  grep -q '^Timestamp=' <<< "${details}" || die "${target} has no secure timestamp"
  grep -qx "TeamIdentifier=${CLI_MACOS_TEAM_ID}" <<< "${details}" || die "${target} isn't signed by Team ${CLI_MACOS_TEAM_ID}"
  grep -qx "Identifier=${identifier}" <<< "${details}" || die "${target} doesn't carry the identifier ${identifier}"
  grep -q 'flags=.*runtime' <<< "${details}" || die "${target} lacks the hardened runtime"
  codesign --verify --strict -R "${requirement}" "${bin}" || die "${target} doesn't meet the requirement ${requirement}"

  zip="${work}/fabric-${target}.zip"
  submission="${notary_dir}/${target}.submit.json"
  ditto -c -k --keepParent "${bin}" "${zip}" || die "ditto failed for ${target}"
  # The submission's id and status are read whatever notarytool exits with,
  # and the log is fetched when there is an id, so a failure names both.
  submitted=0
  xcrun notarytool submit "${zip}" "${notary_auth[@]}" --wait --timeout 1h --output-format json > "${submission}" ||
    submitted=$?
  id="$(sed -n 's/.*"id" *: *"\([0-9a-f-]*\)".*/\1/p' "${submission}" | head -n 1)"
  status="$(sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' "${submission}" | head -n 1)"
  [ -n "${id}" ] || die "notarytool submit failed for ${target} (exit ${submitted}) with no submission id, see ${submission}"
  log="${notary_dir}/${target}.log.json"
  if ! xcrun notarytool log "${id}" "${notary_auth[@]}" "${log}"; then
    note "could not fetch the notary log for ${target} (submission ${id})"
    log="${submission}"
  fi
  if [ "${submitted}" -ne 0 ] || [ "${status}" != "Accepted" ]; then
    die "notarizing ${target} failed: status '${status:-unknown}', submission ${id}, notarytool exit ${submitted}, see ${log}"
  fi

  # Gatekeeper's own check for a program run from a terminal. If it won't
  # assess a bare binary that isn't stapled, the signature alone is assessed
  # as a downloaded file instead. Either must see a notarized Developer ID.
  assessment=""
  if verdict="$(spctl --assess --type execute -vv "${bin}" 2>&1)" && grep -q 'source=Notarized Developer ID' <<< "${verdict}"; then
    assessment="spctl --assess --type execute"
  else
    note "spctl --assess --type execute for ${target}: ${verdict}"
    if verdict="$(spctl --assess --type open --context context:primary-signature -vv "${bin}" 2>&1)" &&
      grep -q 'source=Notarized Developer ID' <<< "${verdict}"; then
      assessment="spctl --assess --type open --context context:primary-signature"
    else
      die "spctl doesn't see a notarized Developer ID for ${target}: ${verdict}"
    fi
  fi
  note "${target}: signed, notarized (${id}), passed ${assessment}"
done
