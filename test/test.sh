#!/bin/bash

nodepy ./server.py &
SERVER_ID=$!
sleep 1

SSH_ORIGINAL_COMMAND="git-receive-pack JohnSmith/somerepo.git" \
  git-auth-client auth.sock --type ssh --username JohnSmith --key-id foo

kill $SERVER_ID
