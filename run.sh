#!/bin/bash
cd ~/SLOWTRACE
source .venv/bin/activate
export SLOWTRACE_LIVE=1
streamlit run dashboard/app.py --server.headless true --server.address localhost
