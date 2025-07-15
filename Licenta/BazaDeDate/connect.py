import pyodbc

# Detaliile conexiunii
server = '2648-ATM-5604N'  # sau adresa serverului tău
database = 'EMAILSYSTEM'  # înlocuiește cu numele bazei tale de date

# Crearea conexiunii
connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;'
try:
    conn = pyodbc.connect(connection_string)
    print("Conexiune reușită!")

    # Crearea unui cursor pentru a executa interogări
    cursor = conn.cursor()

    # Executarea unei interogări
    cursor.execute('SELECT * FROM Users')  # Schimbă cu tabela dorită

    # Obținerea rezultatelor
    rows = cursor.fetchall()
    for row in rows:
        print(row)

    # Închiderea cursorului și a conexiunii
    cursor.close()
    conn.close()

except pyodbc.Error as e:
    print("Eroare la conectare: ", e)
