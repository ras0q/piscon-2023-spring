#!/bin/sh

set -aex

cd webapp/go
go build -o ./isulibrary
sudo systemctl restart isulibrary-go.service
