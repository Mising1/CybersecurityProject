cd "$(dirname "$0")"
tmux new-session -d -s dev -n db  'podman start -a surrealdb_dev'
tmux new-window  -t dev -n api    'cd backend && cargo run'
tmux new-window  -t dev -n web    'cd frontend && npm run dev'
tmux attach -t dev