#!/bin/bash

SESSION_NAME="qdroid_deploy"

echo "Starting tmux session: $SESSION_NAME"
tmux new-session -d -s $SESSION_NAME

tmux send-keys -t $SESSION_NAME "
echo 'Starting deployment with COMPOSE_BAKE=true...';
export COMPOSE_BAKE=true;
docker compose up --build -d;
EXIT_CODE=\$?;
if [ \$EXIT_CODE -eq 0 ]; then
  echo 'Deployment completed successfully.';
else
  echo 'Deployment failed with exit code' \$EXIT_CODE;
fi
sleep 2;
tmux kill-session -t $SESSION_NAME
" C-m

echo "Deployment started in background tmux session '$SESSION_NAME'."
echo "You can monitor it with: tmux attach -t $SESSION_NAME"
