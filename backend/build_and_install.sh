#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "Error: python3/python not found in PATH." >&2
    exit 1
  fi
fi

FRONTEND_DIR="${FRONTEND_DIR:-"$SCRIPT_DIR/../frontend"}"
BACKEND_STATIC_DIR="${BACKEND_STATIC_DIR:-"$SCRIPT_DIR/aida_cli/static"}"
SKILLS_DIR="${SKILLS_DIR:-"$SCRIPT_DIR/../skills"}"
BACKEND_SKILLS_DIR="${BACKEND_SKILLS_DIR:-"$SCRIPT_DIR/aida_cli/skills"}"
FRONTEND_MODE="${FRONTEND_MODE:-auto}"

build_frontend() {
  if [[ "$FRONTEND_MODE" == "never" ]]; then
    echo "Frontend build disabled (FRONTEND_MODE=never)."
    return 0
  fi

  if [[ ! -d "$FRONTEND_DIR" ]]; then
    echo "Frontend directory not found. Skipping frontend build."
    return 0
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "Warning: npm not found. Skipping frontend build."
    return 0
  fi

  echo "Found frontend directory. Building frontend..."
  pushd "$FRONTEND_DIR" >/dev/null

  if [[ -f "package-lock.json" ]]; then
    echo "Running npm ci..."
    if ! npm ci; then
      popd >/dev/null
      if [[ "$FRONTEND_MODE" == "always" ]]; then
        echo "Error: frontend dependency install failed." >&2
        exit 1
      fi
      echo "Warning: frontend dependency install failed. Skipping frontend build."
      return 0
    fi
  else
    echo "Running npm install..."
    if ! npm install; then
      popd >/dev/null
      if [[ "$FRONTEND_MODE" == "always" ]]; then
        echo "Error: frontend dependency install failed." >&2
        exit 1
      fi
      echo "Warning: frontend dependency install failed. Skipping frontend build."
      return 0
    fi
  fi

  echo "Running npm run build..."
  if ! npm run build; then
    popd >/dev/null
    if [[ "$FRONTEND_MODE" == "always" ]]; then
      echo "Error: frontend build failed." >&2
      exit 1
    fi
    echo "Warning: frontend build failed. Skipping frontend build."
    return 0
  fi
  popd >/dev/null

  if [[ ! -d "$FRONTEND_DIR/dist" ]]; then
    if [[ "$FRONTEND_MODE" == "always" ]]; then
      echo "Error: frontend build output not found at '$FRONTEND_DIR/dist'." >&2
      exit 1
    fi
    echo "Warning: frontend build output not found at '$FRONTEND_DIR/dist'. Skipping copy."
    return 0
  fi

  echo "Copying frontend files to backend..."
  rm -rf "$BACKEND_STATIC_DIR"
  mkdir -p "$BACKEND_STATIC_DIR"
  cp -R "$FRONTEND_DIR/dist/." "$BACKEND_STATIC_DIR/"

  if [[ -f "$BACKEND_STATIC_DIR/help.md" ]]; then
    echo "Verified: help.md copied successfully."
  else
    echo "Warning: help.md not found in backend static directory."
  fi
}

build_backend() {
  echo "Cleaning up previous builds..."
  rm -rf dist build aida_cli.egg-info

  if [[ -d "$SKILLS_DIR" ]]; then
    echo "Copying skills into backend package..."
    rm -rf "$BACKEND_SKILLS_DIR"
    mkdir -p "$BACKEND_SKILLS_DIR"
    cp -R "$SKILLS_DIR/." "$BACKEND_SKILLS_DIR/"
  else
    echo "Warning: skills directory not found at '$SKILLS_DIR'."
  fi

  echo "Building package..."
  "$PYTHON_BIN" -m pip install --upgrade build
  "$PYTHON_BIN" -m build
}

install_backend() {
  echo "Installing package..."

  shopt -s nullglob
  local wheels=(dist/*.whl)
  shopt -u nullglob

  if [[ ${#wheels[@]} -eq 0 ]]; then
    echo "Error: No wheel file found under dist/." >&2
    exit 1
  fi

  local whl="${wheels[0]}"
  echo "Found wheel: $whl"
  "$PYTHON_BIN" -m pip uninstall -y "aida-cli"
  "$PYTHON_BIN" -m pip install "$whl"

  echo "Installation complete."
  echo "You can now use the 'aida-cli' command."
  echo "  Example: aida-cli export mybinary.exe -o ./output"
  echo "  Example: aida-cli export mybinary.exe -o ./output --export-c"
  echo "  Example: aida-cli serve ."
}

build_frontend
build_backend
install_backend
