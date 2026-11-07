"""Use SQLite's online backup API instead of copying an active WAL database."""
import argparse
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument("destination")
parser.add_argument("--database", default="/data/lanmark.db")
args = parser.parse_args()
with sqlite3.connect(f"file:{args.database}?mode=ro", uri=True) as source, sqlite3.connect(args.destination) as destination:
    source.backup(destination)
