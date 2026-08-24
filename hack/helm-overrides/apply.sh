#!/bin/bash
# Applies overrides to Helm chart templates and values
#
# Template override format (templates.yaml):
#   <filename>:
#     - search: "<pattern>"
#       replace: "<replacement>"
#
# Values override format (values.yaml):
#   ingress:
#     className: nginx
#     host: gateway.local
#
# Additional templates (hack/helm-templates/):
#   Any .yaml files here are copied to the chart templates directory

set -euo pipefail

# PWD
: ${PWD:="$(cd -P -- "." && pwd -P)"}
# Absolute physical script dir
: ${SCRIPT_DIR:="$(cd -P -- "${BASH_SOURCE[0]%/*}" && pwd -P)"}
: ${CHART_DIR:="charts/cloud-orchestrator-gateway"}
: ${OVERRIDE_FILE:=${1:-$SCRIPT_DIR/templates.yaml}}
: ${VALUES_OVERRIDE_FILE:=${2:-$SCRIPT_DIR/values.yaml}}
: ${EXTRA_TEMPLATES_DIR:=${3:-$SCRIPT_DIR/helm-templates}}
: ${CHART_OVERRIDE_FILE:=${SCRIPT_DIR}/Chart.yaml}
: ${TEMPLATES_DIR:=${CHART_DIR}/templates}
: ${VALUES_FILE:=${CHART_DIR}/values.yaml}
: ${CHART_FILE:=${CHART_DIR}/Chart.yaml}

if [[ ! -d "${PWD}/${CHART_DIR}" ]]; then
  echo "Error: Chart directory not found: ${CHART_DIR}"
  exit 1
fi

# Apply template overrides
# Note: Using perl instead of sed because sed doesn't handle multi-line replacements well
if [[ -f "${OVERRIDE_FILE}" ]]; then
  echo "Applying template overrides from ${OVERRIDE_FILE#$PWD/}"

  while \
    IFS= read -r -d '' file && \
    IFS= read -r -d '' search && \
    IFS= read -r -d '' replace && \
    IFS= read -r -d '' is_regex; do

    # Strip any leading/trailing whitespace or newlines from the filename
    file="${file#"${file%%[![:space:]]*}"}"
    file="${file%"${file##*[![:space:]]}"}"

    TEMPLATE="${TEMPLATES_DIR}/${file}"

    if [[ ! -f "${TEMPLATE}" ]]; then
      printf "  → %-64s ⚠ (file not found)\n" "${file}"
      continue
    fi

    # Must be exported: perl reads these via %ENV, and a plain shell
    # assignment is not part of the child process environment.
    export SEARCH_VAL="${search}"
    export REPLACE_VAL="${replace}"

    # perl -i always exits 0 whether or not anything matched, so the
    # substitution count is reported on stderr (stdout is the rewritten file).
    if [[ "${is_regex}" == "true" ]]; then
      # $1..$N in the replacement are expanded by hand: perl interpolates the
      # replacement once, against the text "$r", so capture references living
      # *inside* $r's value are never rescanned. Snapshot @{^CAPTURE} first —
      # the inner s/// clobbers the capture vars.
      COUNT=$(perl -i -0777 -pe \
        'BEGIN { $s = $ENV{SEARCH_VAL}; $r = $ENV{REPLACE_VAL} }
         $n = s{$s}{
           my @c = @{^CAPTURE};
           my $t = $r;
           $t =~ s/\$\{?([1-9][0-9]*)\}?/defined $c[$1-1] ? $c[$1-1] : ""/ge;
           $t
         }gmse;
         END { print STDERR $n + 0 }' "${TEMPLATE}" 2>&1)
    else
      COUNT=$(perl -i -0777 -pe \
        'BEGIN { $s = $ENV{SEARCH_VAL}; $r = $ENV{REPLACE_VAL} }
         $n = s/\Q$s\E/$r/g;
         END { print STDERR $n + 0 }' "${TEMPLATE}" 2>&1)
    fi

    if [[ "${COUNT}" == "0" ]]; then
      printf "  → %-64s ⚠ (pattern not found)\n" "${file}"
    elif [[ "${COUNT}" =~ ^[0-9]+$ ]]; then
      printf "  → %-64s ✓ (%s)\n" "${file}" "${COUNT}"
    else
      printf "  → %-64s ⚠ (%s)\n" "${file}" "${COUNT}"
    fi
  done < <(yq eval 'to_entries[] | .key as $k | .value[] | [$k, .search, .replace, (.regex // false)] | @json' "${OVERRIDE_FILE}" | jq -j '.[] | (.|tostring) + "\u0000"')
fi

# Apply Chart overrides
if [[ -f "${CHART_OVERRIDE_FILE}" ]]; then
  echo "Merging chart from ${CHART_OVERRIDE_FILE#$PWD/} onto ${CHART_FILE}"
  yq -i '. *= load("'"${CHART_OVERRIDE_FILE}"'")' "${CHART_FILE}"
  printf "  → %-64s ✓\n" "${CHART_FILE##*/}"
fi

# Apply values overrides
if [[ -f "${VALUES_OVERRIDE_FILE}" ]]; then
  echo "Merging values from ${VALUES_OVERRIDE_FILE#$PWD/} onto ${VALUES_FILE}"
  yq -i '. *= load("'"${VALUES_OVERRIDE_FILE}"'")' "${VALUES_FILE}"
  printf "  → %-64s ✓\n" "${VALUES_FILE##*/}"
fi

# Copy extra templates
if [[ -d "${EXTRA_TEMPLATES_DIR}" ]]; then
  #echo "Copying extra templates from ${EXTRA_TEMPLATES_DIR}"
  echo "Copying extra templates from ${EXTRA_TEMPLATES_DIR#$PWD/}"
  # Avoid processing literal glob string if no *.yaml files exist
  shopt -s nullglob

  for template in "${EXTRA_TEMPLATES_DIR}"/*.yaml; do
    cp "${template}" "${TEMPLATES_DIR}/${template##*/}"
    printf "  → %-64s ✓\n" "${template##*/}"
  done

  shopt -u nullglob
fi

echo "✓ Overrides applied"
