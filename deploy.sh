#!/bin/sh

cd webapp/go
go build -o ./isulibrary
sudo systemctl restart isulibrary-go.service
