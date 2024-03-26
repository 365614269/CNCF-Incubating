#!/bin/bash

# CRD docs auto generation script
#
# This script goes through all API definitions in the lifecycle-operator/apis folder
# and generates docs from code for each API group and version
#
# Inputs: None

# renovate: datasource=github-releases depName=elastic/crd-ref-docs
GENERATOR_VERSION=v0.0.12
API_DOMAIN="keptn.sh"
OPERATOR_API_ROOT='lifecycle-operator/apis/'
METRICS_API_ROOT='metrics-operator/api/'
TEMPLATE_DIR='.github/scripts/generate-crd-docs/templates'
RENDERER='markdown'
RENDERER_CONFIG_FILE_TEMPLATE_PATH='.github/scripts/generate-crd-docs/crd-docs-generator-config'
RENDERER_CONFIG_FILE=$RENDERER_CONFIG_FILE_TEMPLATE_PATH'.yaml'
PATH=$PATH:$(go env GOPATH)/bin
DOCS_PATH=./docs/docs/reference/api-reference/

echo "Checking if code generator tool is installed..."
if ! test -s crd-ref-docs; then
  echo "Docs generator is not installed, installing now..."
  go install github.com/elastic/crd-ref-docs@${GENERATOR_VERSION}
else
  echo "Docs generator is installed, continuing..."
fi

echo "Running CRD docs auto-generator..."

for api_group in "$OPERATOR_API_ROOT"*; do

  sanitized_api_group="${api_group#$OPERATOR_API_ROOT}"
  INDEX_PATH="$DOCS_PATH$sanitized_api_group"

  if [ ! -f "$INDEX_PATH/index.md" ]; then
    echo "API group index file doesn't exist for group $sanitized_api_group. Creating it now..."
    # Use sanitized_api_group and make first char uppercase
    API_GROUP="$(tr '[:lower:]' '[:upper:]' <<< "${sanitized_api_group:0:1}")${sanitized_api_group:1}"
    export API_GROUP
    mkdir -p "$INDEX_PATH"
    envsubst < './.github/scripts/generate-crd-docs/templates/index-template.md' > "$INDEX_PATH/index.md"
    unset API_GROUP
  fi
  for api_version in "$api_group"/*; do
    sanitized_api_version="${api_version#$OPERATOR_API_ROOT$sanitized_api_group/}"

    OUTPUT_PATH="$DOCS_PATH$sanitized_api_group/$sanitized_api_version"

    renderer_config_file="$RENDERER_CONFIG_FILE_TEMPLATE_PATH-$sanitized_api_group-$sanitized_api_version.yaml"
    if [ ! -f "$renderer_config_file" ]; then
      echo "Using default configuration..."
      renderer_config_file=$RENDERER_CONFIG_FILE
    else
      echo "Using API version specific configuration..."
    fi


    echo "Arguments:"
    echo "TEMPLATE_DIR: $TEMPLATE_DIR"
    echo "OPERATOR_API_ROOT: $OPERATOR_API_ROOT"
    echo "API_GROUP: $sanitized_api_group"
    echo "API_VERSION: $sanitized_api_version"
    echo "RENDERER: $RENDERER"
    echo "RENDERER_CONFIG_FILE: $renderer_config_file"
    echo "OUTPUT_PATH: $OUTPUT_PATH/index.md"

    echo "Creating docs folder $OUTPUT_PATH..."
    mkdir -p "$OUTPUT_PATH"

    echo "Generating CRD docs for $sanitized_api_group.$API_DOMAIN/$sanitized_api_version..."
    # max-depth should be bumped when the number of nested structures of CRDs will exceed 10
    crd-ref-docs \
      --templates-dir "$TEMPLATE_DIR" \
      --source-path="./$api_version" \
      --renderer="$RENDERER" \
      --config "$renderer_config_file" \
      --max-depth 15 \
      --output-path "$OUTPUT_PATH/index.md"
    echo "---------------------"
  done
done

# Metrics API


sanitized_api_group="metrics"
INDEX_PATH="$DOCS_PATH$sanitized_api_group"

if [ ! -f "$INDEX_PATH/index.md" ]; then
  echo "API group index file doesn't exist for group $sanitized_api_group. Creating it now..."
  # Use sanitized_api_group and make first char uppercase
  API_GROUP="$(tr '[:lower:]' '[:upper:]' <<< "${sanitized_api_group:0:1}")${sanitized_api_group:1}"
  export API_GROUP
  mkdir -p "$INDEX_PATH"
  envsubst < './.github/scripts/generate-crd-docs/templates/index-template.md' > "$INDEX_PATH/index.md"
  unset API_GROUP
fi

for api_version in "$METRICS_API_ROOT"*; do
  sanitized_api_version="${api_version#$METRICS_API_ROOT}"
  OUTPUT_PATH="$DOCS_PATH$sanitized_api_group/$sanitized_api_version"

  echo "Arguments:"
  echo "TEMPLATE_DIR: $TEMPLATE_DIR"
  echo "METRICS_API_ROOT: $METRICS_API_ROOT"
  echo "API_GROUP: $sanitized_api_group"
  echo "API_VERSION: $sanitized_api_version"
  echo "RENDERER: $RENDERER"
  echo "RENDERER_CONFIG_FILE: $RENDERER_CONFIG_FILE"
  echo "OUTPUT_PATH: $OUTPUT_PATH/index.md"

  echo "Creating docs folder $OUTPUT_PATH..."
  mkdir -p "$OUTPUT_PATH"

  echo "Generating CRD docs for $sanitized_api_group.$API_DOMAIN/$sanitized_api_version..."
  # max-depth should be bumped when the number of nested structures of CRDs will exceed 10
  crd-ref-docs \
    --templates-dir "$TEMPLATE_DIR" \
    --source-path="./$api_version" \
    --renderer="$RENDERER" \
    --config "$RENDERER_CONFIG_FILE" \
    --max-depth 15 \
    --output-path "$OUTPUT_PATH/index.md"
  echo "---------------------"
done
