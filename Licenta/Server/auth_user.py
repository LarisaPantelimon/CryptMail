import pyodbc
import bcrypt

def validate(email, plaintext_password):
    connection_string = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=2648-ATM-5604N;DATABASE=EMAILSYSTEM;Trusted_Connection=yes;'
    
    try:
        conn = pyodbc.connect(connection_string)
        cursor = conn.cursor()

        query = "SELECT Password_User FROM Users WHERE Email = ?"
        cursor.execute(query, (email,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return {"authenticated": False}  

        stored_hashed_password = row[0]

        if not bcrypt.checkpw(plaintext_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            conn.close()
            return {"authenticated": False}  

        query = "SELECT Private_Key FROM Private_Key_Ring WHERE UserEmail = ?"
        cursor.execute(query, (email,))
        key_row = cursor.fetchone()

        private_key = key_row[0] if key_row else None  
        conn.close()

        return {
            "authenticated": True,
            "private_key": private_key  
        }
    
    except pyodbc.Error as e:
        print("Database error:", e)
        return {"authenticated": False}
