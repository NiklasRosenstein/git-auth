#!/bin/bash

nodepy ./server.py &
SERVER_ID=$!
sleep 1

SSH_ORIGINAL_COMMAND="git-receive-pack JohnSmith/somerepo.git" \
  git-auth-client auth.sock --type ssh --username JohnSmith --key-id foo >> /dev/null
if [ $? != 0 ]; then exit "JohnSmith/somerepo.git should be accessible."; fi

SSH_ORIGINAL_COMMAND="git-receive-pack EpicStuff/epic.git" \
  git-auth-client auth.sock --type ssh --username JohnSmith --key-id foo >> /dev/null
if [ $? == 0 ]; then exit "EpicStuff/epic.git should not be accessible."; fi

kill $SERVER_ID
echo "Successfull in all testcases."
