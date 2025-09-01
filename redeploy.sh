#!/bin/bash

# Name des Volumes
VOLUME_NAME="jfapp_jfapp-app"

echo ">>> Container stoppen (aber Volumes behalten)..."
docker compose down

echo ">>> Lösche nur das Volume: $VOLUME_NAME"
docker volume rm "$VOLUME_NAME" || echo "Volume $VOLUME_NAME nicht gefunden."
#docker volume ls --filter name=jfapp -q | xargs -r docker volume rm

echo ">>> Neu bauen und starten..."
#docker compose build --no-cache
docker compose up -d --build

echo ">>> Logs (Strg+C zum Beenden)"
docker compose logs -f