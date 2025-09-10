import sqlite3

conn = sqlite3.connect('redteam_automation.db')
cursor = conn.cursor()

# Check what tables exist
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print('Available tables:')
for table in tables:
    print(f'- {table[0]}')

print('\n' + '='*50 + '\n')

# If findings table exists, check its structure
if any('findings' in str(table) for table in tables):
    cursor.execute("PRAGMA table_info(findings);")
    columns = cursor.fetchall()
    print('Findings table structure:')
    for col in columns:
        print(f'- {col[1]} ({col[2]})')
else:
    print('No findings table found')

conn.close()