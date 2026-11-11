#!/bin/sh
set -e
cd "$(dirname "$0")"
mkdir -p dist
{ printf '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
  sed -n '1,/<\/style>/p' index.html
  printf '</head><body>\n'
  sed -n '/<\/style>/,$p' index.html | tail -n +2
  printf '</body></html>\n'; } > dist/index.html
echo "wrote site/dist/index.html"
