import sqlite3
import shutil
from pathlib import Path
from datetime import datetime


def init_db(db_path: Path, sql_path: Path, backup: bool = True) -> None:
    """
    Initialize the SQLite database using the provided SQL script.
    If backup=True, creates a backup of existing database before reinitializing.
    """
    # Create backup if database exists and backup requested
    if db_path.exists() and backup:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = db_path.parent / f"app_backup_{timestamp}.db"
        shutil.copy2(db_path, backup_path)
        print(f"Backup created: {backup_path}")
    
    sql = sql_path.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            conn.executescript(sql)
    finally:
        conn.close()


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    db_file = base_dir / "app.db"
    sql_file = base_dir / "init_db.sql"

    init_db(db_file, sql_file)
    print(f"Database created at {db_file}")

