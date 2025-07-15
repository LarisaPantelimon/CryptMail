import aioodbc
import bcrypt
from datetime import datetime

class Database:
    _instance = None  # Singleton instance

    def __new__(cls, server='mobile-sqlserver', database='EMAIL_MOBILE', user='sa', password='Pantelimon2002*'):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance.server = server
            cls._instance.database = database
            cls._instance.user = user
            cls._instance.password = password
            # Conexiune cu autentificare SQL
            cls._instance.connection_string = (
                f'DRIVER={{ODBC Driver 17 for SQL Server}};'
                f'SERVER={server};'
                f'PORT=1433;'
                f'DATABASE={database};'
                f'UID={user};'
                f'PWD={password}'
            )
        return cls._instance

    async def get_connection(self):
        """Create a new async database connection."""
        try:
            return await aioodbc.connect(dsn=self.connection_string)
        except Exception as e:
            print(f"Database connection error: {e}")
            raise

async def handle_register_db(db, payload):
    email = payload.get("email")
    password = payload.get("password")
    fullName = payload.get("fullName")
    gender = payload.get("gender")
    birthdate = payload.get("birthday")
    phone = payload.get("phone")
    tokenDevice = payload.get("tokenDevice")

    if not email or not password:
        return {"success": False, "message": "Email and password are required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if email already exists
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if await cursor.fetchone():
            return {"success": False, "message": "Email already registered"}

        # Insert new user
        birthday_datetime = datetime.strptime(birthdate, "%d/%m/%Y")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        await cursor.execute(
            "INSERT INTO Accounts (Email, Password_User, NameUser, Birthday, Gender, PhoneNumber, DeviceToken) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (email, hashed_password, fullName, birthday_datetime, gender, phone, tokenDevice)
        )
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()

async def handle_login_db(db, payload):
    email = payload.get("email")
    password = payload.get("password")
    tokenDevice = payload.get("tokenDevice")

    if not email or not password:
        return {"success": False, "message": "Email and password are required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if email exists
        await cursor.execute("SELECT Password_User FROM Accounts WHERE Email = ?", (email,))
        row = await cursor.fetchone()

        if not row:
            return {"success": False, "message": "Email not registered"}

        hashed_password = row[0]
        print(f"Hashed password from DB: {hashed_password}")

        # Verify password (bcrypt is synchronous, run in executor if needed)
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            # Update device token
            await cursor.execute("UPDATE Accounts SET DeviceToken = ? WHERE Email = ?", (tokenDevice, email))
            await connection.commit()
            return {"success": True}
        else:
            return {"success": False, "message": "Invalid password"}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()

async def handle_save_email_account(db, payload):
    email = payload.get("email")
    emailToBeSaved = payload.get("emailToBeSaved")

    if not email or not emailToBeSaved:
        return {"success": False, "message": "Email and email_account are required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if email exists in Accounts
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if not await cursor.fetchone():
            return {"success": False, "message": "Email not registered"}

        # Check if the pair already exists
        await cursor.execute("SELECT 1 FROM Emails WHERE Email_Acc = ? AND EmailToAdd = ?", (email, emailToBeSaved))
        if await cursor.fetchone():
            return {"success": False, "message": "This email pair is already saved"}

        # Insert pair
        await cursor.execute("INSERT INTO Emails (Email_Acc, EmailToAdd) VALUES (?, ?)", (email, emailToBeSaved))
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()

async def handle_get_user_info(db, payload):
    email = payload.get("email")

    if not email:
        return {"success": False, "message": "Email is required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if email exists
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if not await cursor.fetchone():
            return {"success": False, "message": "Email not registered"}

        # Fetch user info
        await cursor.execute("SELECT NameUser, Birthday, Gender, PhoneNumber FROM Accounts WHERE Email = ?", (email,))
        row = await cursor.fetchone()

        if row:
            nameUser, birthday, gender, phoneNumber = row
            birthday_str = birthday.strftime("%d/%m/%Y") if birthday else None
            return {
                "success": True,
                "emailaddress": email,
                "fullName": nameUser,
                "gender": gender,
                "phoneNumber": phoneNumber,
                "birthday": birthday_str
            }
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()

async def handle_update_info_user(db, payload):
    email = payload.get("emailaddress")
    fullName = payload.get("fullName")
    gender = payload.get("gender")
    phone = payload.get("phoneNumber")
    birthday = payload.get("birthday")

    if not email:
        return {"success": False, "message": "Email is required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Verify if the user exists
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if not await cursor.fetchone():
            return {"success": False, "message": "Email not registered"}

        birthday_datetime = datetime.strptime(birthday, "%d/%m/%Y")
        await cursor.execute(
            "UPDATE Accounts SET NameUser=?, Birthday=?, Gender=?, PhoneNumber=? WHERE Email=?",
            (fullName, birthday_datetime, gender, phone, email)
        )
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()

async def handle_get_account_info(db, payload):
    email = payload.get("email")

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Verify if the user exists
        await cursor.execute("SELECT Email_Acc FROM Emails WHERE EmailToAdd = ?", (email,))
        rows = await cursor.fetchall()

        if not rows:
            return {"success": False, "message": "Email not registered"}

        pairs = []
        for row in rows:
            email_str = row[0]
            await cursor.execute("SELECT Email, DeviceToken FROM Accounts WHERE Email = ?", (email_str,))
            result = await cursor.fetchone()
            if result:
                pairs.append(result)

        return {"success": True, "pairs": pairs}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()
            
async def handle_find_one(db, payload):
    email = payload.get("email")

    if not email :
        return {"success": False, "message": "Email is required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if the pair exists
        await cursor.execute("SELECT 1 FROM Emails WHERE Email_Acc = ?", (email))
        if not await cursor.fetchone():
            return {"success": False, "message": "This email does not exist"}
        else:
            return {"success": True, "message": "This email exists"}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()
            
async def handle_reset_password_db(db,payload):
    email= payload.get("email")
    new_password= payload.get("newPassword")
    if not email or not new_password:
        return {"success": False, "message": "Email and new password are required"}
    
    connection= None
    cursor= None
    
    try:
        connection= await db.get_connection()
        cursor= await connection.cursor()
        
        # Check if email exists
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if not await cursor.fetchone():
            return {"success": False, "message": "Email not registered"}
        
        # Update password
        hashed_password= bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        await cursor.execute("UPDATE Accounts SET Password_User = ? WHERE Email = ?", (hashed_password, email))
        await connection.commit()
        
        return {"success": True}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()
            
async def handle_delete_account(db, payload):
    email = payload.get("email")

    if not email:
        return {"success": False, "message": "Email is required"}

    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if email exists
        await cursor.execute("SELECT 1 FROM Accounts WHERE Email = ?", (email,))
        if not await cursor.fetchone():
            return {"success": False, "message": "Email not registered"}

        # Delete account
        await cursor.execute("DELETE FROM Accounts WHERE Email = ?", (email,))
        await connection.commit()

        return {"success": True}
    except Exception as e:
        print(f"Error: {e}")
        return {"success": False, "message": str(e)}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await connection.close()