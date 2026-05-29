#!/bin/sh
set -e

# Setup optional labs root. When CLAB_LABS_ROOT is unset, the API server
# stores managed lab files in each authenticated user's ~/.clab directory.
if [ -n "${CLAB_LABS_ROOT:-}" ]; then
  echo "Setting up labs root: $CLAB_LABS_ROOT"
  mkdir -p "$CLAB_LABS_ROOT"
fi

mkdir -p /var/run/netns

# Now execute the command passed to the container
echo "Executing command: $@"
exec "$@"
