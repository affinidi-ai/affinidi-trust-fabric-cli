#!/usr/bin/env bash
# Pushes the git note semantic-release keeps for a release tag again, for
# example `scripts/push-release-notes.sh v0.2.0`. scripts/release.sh runs this
# when semantic-release fails, because the last thing semantic-release pushes
# is the note, after the release commit and the tag. If GitHub refuses only
# that push, the release has already happened, the tag has started the release
# workflow, and a run of the version workflow by hand finds nothing to release
# and never pushes the note.
#
# This only acts on that one case: the tag is on origin at the commit it marks
# here, the note semantic-release made is here, and origin has no note for the
# tag yet. The push is then tried up to RELEASE_NOTES_ATTEMPTS times (3 by
# default), RELEASE_NOTES_RETRY_DELAY seconds apart (10 by default, doubling
# each time).
#
# Exits 0 once the note is pushed, 1 if every push failed, and 2 if the failure
# isn't this case, so the caller keeps semantic-release's own error.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <vX.Y.Z>" >&2
  exit 2
fi
tag="$1"
if ! [[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: the tag must look like v1.2.3, got '${tag}'" >&2
  exit 2
fi
attempts="${RELEASE_NOTES_ATTEMPTS:-3}"
delay="${RELEASE_NOTES_RETRY_DELAY:-10}"
if ! [[ "${attempts}" =~ ^[1-9]$ ]] || ! [[ "${delay}" =~ ^[0-9]{1,3}$ ]]; then
  echo "error: RELEASE_NOTES_ATTEMPTS must be 1 to 9 and RELEASE_NOTES_RETRY_DELAY 0 to 999 seconds" >&2
  exit 2
fi
notes_ref="refs/notes/semantic-release-${tag}"

commit="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}" || true)"
if [ -z "${commit}" ]; then
  echo "No tag ${tag} here, so the failure wasn't the push of its note" >&2
  exit 2
fi
if ! git notes --ref "${notes_ref}" show "refs/tags/${tag}" > /dev/null 2>&1; then
  echo "semantic-release made no note for ${tag} here, so the failure came before the push of its note" >&2
  exit 2
fi

# ls-remote lists an annotated tag's own object and, as <tag>^{}, the commit it
# marks; a lightweight tag only once. The last line is the commit either way.
if ! remote_tag="$(git ls-remote origin "refs/tags/${tag}" "refs/tags/${tag}^{}")" \
  || ! remote_notes="$(git ls-remote origin "${notes_ref}")"; then
  echo "error: could not read the tag and note of ${tag} on origin" >&2
  exit 2
fi
remote_commit="$(tail -n 1 <<< "${remote_tag}" | cut -f 1)"
if [ "${remote_commit}" != "${commit}" ]; then
  echo "origin doesn't have ${tag} at ${commit}, so the failure wasn't the push of its note" >&2
  exit 2
fi
if [ -n "${remote_notes}" ]; then
  echo "origin already has ${notes_ref}, so semantic-release failed after pushing it" >&2
  exit 2
fi

echo "${tag} is released, but origin has no ${notes_ref}; pushing it again"
attempt=1
while true; do
  if git push origin "${notes_ref}"; then
    echo "::warning::${tag} is released. GitHub refused the push of ${notes_ref} from semantic-release, and attempt ${attempt} of ${attempts} pushed it."
    exit 0
  fi
  if [ "${attempt}" -ge "${attempts}" ]; then
    break
  fi
  echo "Attempt ${attempt} of ${attempts} to push ${notes_ref} failed; trying again in ${delay}s" >&2
  sleep "${delay}"
  delay=$((delay * 2))
  attempt=$((attempt + 1))
done

echo "::error::${tag} is released (tag and release commit are on GitHub), but ${notes_ref} could not be pushed after ${attempts} attempts. semantic-release only uses the note to know the release channel, so nothing else is missing. To add it, from a checkout with write access: git fetch origin --tags && git notes --ref semantic-release-${tag} add -f -m '{\"channels\":[null]}' ${tag} && git push origin ${notes_ref}" >&2
exit 1
