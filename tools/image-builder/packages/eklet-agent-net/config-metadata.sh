#!/bin/bash
# Initialize Metadata

source "/opt/eklet-agent/config-fun.sh"

function read_metadata_again() {
  local data_path="/opt/eklet-agent/user-data"
  [[ ! -s ${data_path} ]] && echo "failed to get user data: ${data_path} is empty" && return

  read_user_data ${data_path}
  ## TODO: update metric port if need
  echo "get user data success"
}

read_metadata_again
