import sqlite3
import requests
from urllib.parse import urlparse

class Pathfinder:
    def __init__(self, db_path='pathfinder.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS paths (
                path TEXT PRIMARY KEY,
                technology TEXT
            )
        ''')
        self.conn.commit()

    def load_paths(self, paths, technology):
        cursor = self.conn.cursor()
        cursor.executemany('''
            INSERT OR IGNORE INTO paths (path, technology)
            VALUES (?, ?)
        ''', [(path, technology) for path in paths])
        self.conn.commit()

    def discover_via_wayback(self, domain):
        url = f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey'
        response = requests.get(url)
        if response.status_code == 200:
            paths = response.json()
            return [urlparse(path[0]).path for path in paths[1:]]
        return []

    def find_paths(self, tech):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT path FROM paths WHERE technology = ?
        ''', (tech,))
        return [row[0] for row in cursor.fetchall()]

    def close(self):
        self.conn.close()
