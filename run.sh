#!/bin/bash
cd ~/SLOWTRACE
source .venv/bin/activate
streamlit run dashboard/app.py --server.headless true --server.address localhost
