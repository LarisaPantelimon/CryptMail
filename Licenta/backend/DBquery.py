import asyncodbc
import bcrypt
from datetime import datetime
import asyncio
from dotenv import load_dotenv
import os

# import aiomysql
load_dotenv()

class Database:
    _instance = None  # Singleton instance
    pool = None  # Connection pool

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            # Cite?te connection string din .env
            cls._instance.connection_string = os.getenv('DATABASE_URL')
            if not cls._instance.connection_string:
                raise ValueError("DATABASE_URL nu este setat in fisierul .env")
            # Initialize the pool synchronously by running the async init_pool
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is already running (e.g., in Quart), create a task
                asyncio.create_task(cls._instance.init_pool())
            else:
                # Run synchronously for testing or non-async contexts
                loop.run_until_complete(cls._instance.init_pool())
        return cls._instance

    async def init_pool(self):
        """Initialize the connection pool."""
        if self.pool is None:
            try:
                self.pool = await asyncodbc.create_pool(
                    dsn=self.connection_string,
                    minsize=1,  # Minimum number of connections
                    maxsize=100  # Maximum number of connections
                )
                print("Database pool initialized successfully")
            except Exception as e:
                print(f"Failed to initialize database pool: {str(e)}")
                raise

    async def get_connection(self):
        """Get a connection from the pool."""
        if self.pool is None:
            raise ValueError("Database pool is not initialized")
        return await self.pool.acquire()

    async def close_pool(self):
        """Close the connection pool."""
        if self.pool is not None:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None
            

async def handle_auth_request(db, email, password):
    connection = None
    cursor = None

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        print(f"Authentication request for user: {email}")

        query = "SELECT Password_User, TwoFactor FROM Users WHERE Email = ?"
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()

        if not row:
            print(f"User not found: {email}")
            return {"success": False, "error": "User not found"}

        stored_hashed_password, two_factor = row

        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            print(f"Password mismatch for user: {email}")
            query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query, ("LOGIN FAILED", email))
            await connection.commit()
            return {"success": False, "error": "Invalid credentials provided"}

        query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("LOGIN SUCCESS", email))
        await connection.commit()
        return {"success": True, "two_factor": two_factor}

    except Exception as e:
        print(f"Database error: {str(e)}")
        if cursor and connection:
            query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query, ("LOGIN FAILED", email))
            await connection.commit()
        return {"success": False, "error": "Database error occurred"}

    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_fetch_emails(db, request):
    connection = None
    cursor = None

    try:
        recipient = request.get("email")
        print(f"Fetching emails for: {recipient}")

        if not recipient:
            return {"success": False, "error": "Recipient email not provided"}

        emails_sent = []
        emails_received = []

        connection = await db.get_connection()
        cursor = await connection.cursor()

        query_emails_sent = """
        SELECT EmailSentId, Sender, Receiver, SentDate, IsRead, Folder, SubjectMail
        FROM EmailsSent
        WHERE Sender = ?
        """
        try:
            await cursor.execute(query_emails_sent, (recipient,))
            rows = await cursor.fetchall()

            for row in rows:
                email = {
                    "EmailSentId": row[0],
                    "Sender": row[1],
                    "Receiver": row[2],
                    "SentDate": row[3],
                    "IsRead": row[4],
                    "Folder": row[5],
                    "Subject": row[6]
                }
                emails_sent.append(email)
        except Exception as e:
            print(f"Error fetching sent emails from database: {str(e)}")
            return {"success": False, "error": "Error fetching sent emails from database"}

        query_emails_received = """
        SELECT EmailReceivedId, Sender, Receiver, SentDate, IsRead, Folder, SubjectMail
        FROM EmailsReceived
        WHERE Receiver = ?
        """
        try:
            await cursor.execute(query_emails_received, (recipient,))
            rows = await cursor.fetchall()

            for row in rows:
                email = {
                    "EmailReceivedId": row[0],
                    "Sender": row[1],
                    "Receiver": row[2],
                    "SentDate": row[3],
                    "IsRead": row[4],
                    "Folder": row[5],
                    "Subject": row[6]
                }
                emails_received.append(email)
        except Exception as e:
            print(f"Error fetching received emails from database: {str(e)}")
            return {"success": False, "error": "Error fetching received emails from database"}

        return {
            "success": True,
            "emails_sent": emails_sent,
            "emails_received": emails_received
        }

    except Exception as e:
        print(f"Error fetching emails: {str(e)}")
        return {"success": False, "error": "Failed to fetch emails"}

    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_update_folder(db,request):
    connection = None
    cursor = None
    email_id = request.get("email_id")
    new_folder = request.get("newfolder")
    sender=request.get("sender")
    myemail=request.get("myemail")
    receiver=request.get("receiver")
    
    # if i am the sender i will look into the Sent Emails table
    try:    
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()
        if sender==myemail:
            query = "UPDATE EmailsSent SET Folder = ? WHERE EmailSentId = ?"
            await cursor.execute(query, (new_folder, email_id))
        if receiver==myemail:
            query = "UPDATE EmailsReceived SET Folder = ? WHERE EmailReceivedId = ?"
            await cursor.execute(query, (new_folder, email_id))    
        if sender!=myemail:
            query = "UPDATE EmailsReceived SET Folder = ? WHERE EmailReceivedId = ?"
            await cursor.execute(query, (new_folder, email_id))
            
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("UPDATE FOLDER",myemail))
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print("Error updating folder in database:", e)
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("UPDATE FOLDER FAILED",myemail))
        await connection.commit()
        
        return {"success": False,"error": "Error updating folder in database"}
    except Exception as e:
        print(f"Error updating folder: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("UPDATE FOLDER FAILED",myemail))
        await connection.commit()
        return {"success": False,"error": "Failed to update folder."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_delete_email(db,request):
    connection = None
    cursor = None
    email_id = request.get("email_id")
    sender=request.get("sender")
    myemail=request.get("email")
    receiver=request.get("receiver")
    
    # if i am the sender i will look into the Sent Emails table
    try:    
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()
        if sender==myemail:
            query = "DELETE FROM EmailsSent WHERE EmailSentId =?"
            await cursor.execute(query, (email_id,))
        if myemail==receiver:
            query = "DELETE FROM EmailsReceived WHERE EmailReceivedId =?"
            await cursor.execute(query, (email_id,))
        if sender!=myemail:
            query = "DELETE FROM EmailsReceived WHERE EmailReceivedId =?"
            await cursor.execute(query, (email_id,))
        
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("EMAIL DELETED"),myemail)
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print("Error deleting email from database:", e)
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("DELETE EMAIL FAILED"),myemail)
        await connection.commit()
        
        return {"success": False,"error": "Error deleting email from database"}
    except Exception as e:
        print(f"Error deleting email: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("DELETE EMAIL FAILED"),myemail)
        await connection.commit()
        return {"success": False,"error": "Failed to delete email."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_get_last_key(db, request):
    connection = None
    cursor = None
    email = request.get("receiver_email")
    print(f"Retrieving the last public key for user: {email}")
    
    try:
        query = """
            SELECT TOP 1 Public_Key, KeyId, ExpirationDate 
            FROM Public_Key_Ring 
            WHERE UserEmail = ? 
            AND ExpirationDate >= GETDATE()
            ORDER BY Timestamp DESC;
        """
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        
        if row:
            public_key, key_id, expiration_date = row
            return {"success": True, "PubKey": public_key, "KeyId": key_id, "ExpirationDate": expiration_date}
        else:
            return {"success": False, "error": "Your Public key has expired! Please generate a new one from the Profile Settings!"}
    except Exception as e:
        print(f"Error retrieving public key: {e}")
        return {"error": "Failed to retrieve public key"}
    except Exception as e:
        print(f"Error retriving public key: {e}")
        return {"success": False,"error": "Failed to retrive public key."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
     
async def handle_get_all_privatekeys(db, request):
    connection = None
    cursor = None
    email = request.get("email")
    print(f"Retrieving all private keys for user: {email}")
    
    try:
        query = "SELECT Private_Key, KeyId FROM Private_Key_Ring WHERE UserEmail = ?"
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()

        await cursor.execute(query, (email,))
        rows = await cursor.fetchall()

        private_keys = []
        for row in rows:
            private_key = row[0]  # Private_Key is the first column
            key_id = row[1]       # KeyId is the second column
            private_keys.append({"PrivateKey": private_key, "KeyId": key_id})
        
        return {"success": True, "PrivateKeys": private_keys}
    except Exception as e:
        print(f"Error retrieving private keys: {e}")
        return {"error": "Failed to retrieve private keys"}
    except Exception as e:  
        print(f"Error retrieving private keys: {e}")
        return {"success": False,"error": "Failed to retrieve private keys."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection) 
async def handle_get_pubKey(db,request):
    connection = None
    cursor = None
    email = request.get("receiver_email")
    key_id = request.get("key_id")
    print(f"Retrieving public key for user: {email} and key_id: {key_id}")
    
    try:
        query = "SELECT Public_Key FROM Public_Key_Ring WHERE UserEmail = ? AND KeyId = ?"
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()
        
        await cursor.execute(query, (email,key_id))
        row = await cursor.fetchone()  

        if row:
            public_key = row[0] 
            print("Public key found")
            return {"success": True, "PubKey": public_key}
        else:
            return {"success": False, "error": "Public key not found"}
    except Exception as e:
        print(f"Error registering user: {e}")
        return {"success": False,"error": "Failed to register user."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_register(db, request):
    connection = None
    cursor = None

    try:
        # Extract user input
        email = request.get("email")
        password = request.get("password")
        fullName = request.get("fullName")
        phoneNumber = request.get("phoneNumber")
        gender = request.get("gender")
        birthday = request.get("birthday")
        public_key = request.get("public_key")
        private_key = request.get("private_key")
        timestamp = request.get("timestamp")
        key_id = request.get("key_id")
        two_factor = request.get("twoFactor")
        # homomorphic=request.get("homomorphic")
        
        # Convert timestamp if provided
        try:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        except ValueError:
            return {"success": False, "error": "Invalid timestamp format"}

        # Convert birthday if provided
        if birthday:
            try:
                birthday = datetime.strptime(birthday, "%Y-%m-%d").date()
            except ValueError:
                return {"success": False, "error": "Invalid date format for birthday. Use YYYY-MM-DD."}
        else:
            birthday = None

        print(f"Registering user: {email}")

        # Get database connection
        connection = await db.get_connection()
        cursor = await connection.cursor()

        try:
            # Begin transaction
            query = """
                INSERT INTO Users (Email, Password_User, Full_Name, Birthday, Gender, Phone, TwoFactor)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            await cursor.execute(query, (email, password, fullName, birthday, gender, phoneNumber,two_factor))

            query = """
                INSERT INTO Public_Key_Ring (Timestamp, KeyId, Public_Key, UserEmail)
                VALUES (?, ?, ?, ?)
            """
            await cursor.execute(query, (timestamp, key_id, public_key, email))

            query = """
                INSERT INTO Private_Key_Ring (Timestamp, KeyId, Private_Key, UserEmail, Public_Key)
                VALUES (?, ?, ?, ?, ?)
            """
            await cursor.execute(query, (timestamp, key_id, private_key, email,public_key)) 
            
            if two_factor==True:
                query="""
                INSERT INTO TwoFactorInfo (UserEmail, KeysId)
                VALUES (?, ?)"""
                await cursor.execute(query, (email, key_id))

            # Commit the transaction
            query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query,("REGISTER"),email)

            await connection.commit()
            print("User and keys successfully saved to database.")
            return {"success": True}

        except Exception as e:
            print("Database error:", e)
            query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query,("REGISTER FAILED"),email)
            await connection.commit()
              # Rollback on failure
            return {"success": False, "error": "Database error, transaction rolled back"}

    except Exception as e:
        print("Unexpected error:", e)
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("REGISTER FAILED"),email)
        await connection.commit()
        return {"success": False, "error": "An unexpected error occurred"}

    finally:
        # Ensure cursor and connection are closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_send_email(db, request):
    connection = None
    cursor = None
    sender = request.get("from")
    recipient = request.get("to")
    subject = request.get("subject")
    current_datetime = datetime.now()

    print(f"Sending email from: {sender} to: {recipient}")
    
    email_id_sent = 0
    email_id_received = 0
    
    # Get a connection and cursor
    connection = await db.get_connection()
    cursor = await connection.cursor()
    
    try:
        # Check if receiver exists
        query = "SELECT Full_Name FROM Users WHERE Email = ?"
        await cursor.execute(query, (recipient,))  # Ensure tuple syntax
        row = await cursor.fetchone()
        
        if row is None:  # Correct check for no result
            print("User not found!")
            query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query, ("USER NOT FOUND", sender))
            await connection.commit()
            return {"success": False, "error": "User does not exist!"}
        
        print("The user found", row[0])  # Safe to access row[0] now
        
        # Insert into EmailsSent table
        query = """
        INSERT INTO EmailsSent (Sender, Receiver, SentDate, IsRead, Folder, SubjectMail)
        OUTPUT INSERTED.EmailSentId
        VALUES (?, ?, ?, ?, ?, ?)
        """
        await cursor.execute(query, (sender, recipient, current_datetime, 1, "Sent", subject))
        row = await cursor.fetchone()
        email_id_sent = row[0]
        print(email_id_sent)

        
        # Insert into EmailsReceived table
        query = """
        INSERT INTO EmailsReceived (Sender, Receiver, SentDate, IsRead, Folder, SubjectMail)
        OUTPUT INSERTED.EmailReceivedId
        VALUES (?, ?, ?, ?, ?, ?)
        """
        await cursor.execute(query, (sender, recipient, current_datetime, 0, "Inbox", subject))
        row = await cursor.fetchone()
        email_id_received = row[0]
        print(email_id_received)
        
        # Log success and commit
        query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("EMAIL SENT", sender))
        await connection.commit()

        return {
            "success": True,
            "email_id_sent": email_id_sent,
            "email_id_received": email_id_received
        }
    except Exception as e:
        print(f"Error handling email: {e}")
        query = "INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query, ("SEND EMAIL FAILED", sender))
        await connection.commit()
        return {"success": False, "error": "Failed to handle email"}

    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
async def handle_get_user(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    print(f"Retrieving user: {email}")
    connection = await db.get_connection()
    cursor = await connection.cursor()
    
    try:
        query = """SELECT Email, Full_Name, Birthday, Gender, Phone FROM Users WHERE Email = ?"""
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        
        if row:
            email, fullName, birthday, gender, phoneNumber = row
            return {"success": True, "email": email, "fullName": fullName, "birthday": str(birthday) if birthday else None, "gender": gender, "phoneNumber": phoneNumber}
        else:
            return {"success": False, "error": "User not found"}
    except Exception as e:
        print(f"Error retrieving user: {e}")
        return {"success": False,"error": "Failed to retrieve user"}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_update_user(db, request): 
    connection = None
    cursor = None
    old_email = request.get("oldEmail")
    updated_user = request.get("updatedUser")

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor() 
        update_query = "UPDATE Users SET "
        update_fields = []
        params = []
        
        # Dynamically add fields to the query if they are provided
        if 'FullName' in updated_user:
            update_fields.append("Full_Name = ?")
            params.append(updated_user['FullName'])
        if 'PhoneNumber' in updated_user:
            update_fields.append("Phone = ?")
            params.append(updated_user['PhoneNumber'])
        if 'Gender' in updated_user:
            update_fields.append("Gender = ?")
            params.append(updated_user['Gender'])
        if 'Birthday' in updated_user:
            update_fields.append("Birthday = ?")
            params.append(updated_user['Birthday'])
            
        if not update_fields:
            return {"success": False,"error": "No fields to update"}
        
        update_query += ", ".join(update_fields)
        update_query += " WHERE Email = ?"
        params.append(old_email)  # Use the old email to find the user

        # Execute the query
        await cursor.execute(update_query, params)
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("USER UPDATED"),old_email)
        await connection.commit()
        
        if cursor.rowcount == 0:
           return {"success": False,"error": "User not found"}
       
        return {"success": True}
    except Exception as e:
        print(f"Error updating user: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("USER UPDATE FAILED"),old_email)
        await connection.commit()
        return {"success": False,"error": "Failed to update user"}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
                
async def handle_update_password(db, request):
    connection = None
    cursor = None
    email = request.get("email")
    old_password = request.get("old_password")  # Ensure field names match frontend
    new_hashed_password = request.get("newHashedPassword")
    private_keys = request.get("private_keys")  # Array of new encrypted private keys

    print(f"Updating password for user: {email}")

    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()

        # Check if the old password is correct
        query = "SELECT Password_User FROM Users WHERE Email = ?"
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()

        if not row or not bcrypt.checkpw(old_password.encode('utf-8'), row[0].encode('utf-8')):
            return {"success": False, "error": "Incorrect old password"}

        # Update the user's password
        query = "UPDATE Users SET Password_User = ? WHERE Email = ?"
        await cursor.execute(query, (new_hashed_password, email))

        # Update all encrypted private keys
        if private_keys:
            query = "UPDATE Private_Key_Ring SET Private_Key = ? WHERE UserEmail = ? AND KeyId = ?"
            for private_key_obj in private_keys:
                # Extract the KeyId and PrivateKey from the object
                key_id = private_key_obj['KeyId']
                private_key = private_key_obj['PrivateKey']
                await cursor.execute(query, (private_key, email, key_id))
                
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("PASSWORD UPDATED"),email)

        await connection.commit()
        return {"success": True}

    except Exception as e:
        print(f"Unexpected error updating password: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("PASSWORD UPDATE FAILED"),email)
        await connection.commit()
        return {"success": False, "error": "An unexpected error occurred while updating the password."}

    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_generate_newkeys(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    encryptedPrivateKey=request.get("encryptedPrivateKey")
    publicKeyPem=request.get("publicKeyPem")
    timestamp=request.get("timestamp")
    key_id=request.get("key_id")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        query = "INSERT INTO Private_Key_Ring (UserEmail, Private_Key, Public_Key, Timestamp, KeyId) VALUES (?,?,?,?,?)"
        await cursor.execute(query, (email, encryptedPrivateKey, publicKeyPem, timestamp, key_id))
        
        query = """
                INSERT INTO Public_Key_Ring (Timestamp, KeyId, Public_Key, UserEmail)
                VALUES (?, ?, ?, ?)
            """
        await cursor.execute(query, (timestamp, key_id, publicKeyPem, email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("KEY GENERATED"),email)

        await connection.commit()
        
        return {"success": True}
    except Exception as e:
        print(f"Error generating new keys: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("GENERATE KEY FAILED"),email)
        await connection.commit()
        return {"success": False, "error": "Failed to generate new keys"}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
        
async def handle_get_myprivatekey(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    key_id = request.get("key_id")
    print(f"Retrieving private key for user: {email} and key_id: {key_id}")
    
    try:
        query = "SELECT Private_Key FROM Private_Key_Ring WHERE UserEmail = ? AND KeyId = ?"
        connection = await db.get_connection()  # Get a fresh connection
        cursor = await connection.cursor()
        
        await cursor.execute(query, (email,key_id))
        row = await cursor.fetchone()  

        if row:
            private_key = row[0] 
            print("Private key found")
            return {"success": True, "PrivateKey": private_key}
        else:
            print("Private key not found")
            return {"success": False, "error": "Private key not found"}
    except Exception as e:
        print(f"Error registering user: {e}")
        return {"success": False,"error": "Failed to register user."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)       
            
async def handle_save_recovery_email(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    recovery_email=request.get("recovery_email")
    
    try:
        query=""" INSERT INTO Recovery_Credentials(UserEmail, RecoveryEmail)
            VALUES (?, ?)
        """
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        await cursor.execute(query, (email,recovery_email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("RECOVERY MAIL SAVED"),email)

        await connection.commit()
        
        return {"success": True}
    except Exception as e:
        print(f"Error adding recovery email: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("SAVE RECOVERY MAIL FAILED"),email)
        await connection.commit()
        return {"success": False, "error": "Failed to add recovery email."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_update_recovery_email(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    recovery_email=request.get("recovery_email")
    
    try:
        query=""" UPDATE Recovery_Credentials 
            SET RecoveryEmail = ?, Verified = ? 
            WHERE UserEmail = ?;
        """
        connection = await db.get_connection()
        cursor = await connection.cursor()
        await cursor.execute(query, (recovery_email, False, email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("UPDATE RECOVERY MAIL"),email)

        await connection.commit()
        
        return {"success": True}
    except Exception as e:
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("UPDATE RECOVERY MAIL FAILED"),email)
        await connection.commit()
        print(f"Error updating recovery email: {e}")
        return {"success": False, "error": "Failed to update recovery email."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_recovery_email(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query=""" SELECT RecoveryEmail, Verified FROM  Recovery_Credentials
        WHERE UserEmail = ?
        """
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        if row:
            recovery_email,verification=row
            return {"success": True,"recovery_email":recovery_email,"verification":verification}
        else:
            return {"success": True,"recovery_email":None,"verification":False}
    except Exception as e:
        print(f"Error getting recovery email: {e}")
        return {"success": False,"error": "Failed to recovery email."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_mark_recovery_email(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="""UPDATE Recovery_Credentials SET Verified = ? WHERE UserEmail = ?"""
        ceva=True
        await cursor.execute(query, (ceva,email,))
        await connection.commit()
        
        return{"success": True}
    except Exception as e:
        print(f"Error marking recovery email: {e}")
        return {"success": False,"error": "Failed to marking email."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_check_recovery_file(db, request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="""SELECT Used FROM Recovery_Key_Ring
            WHERE UserEmail = ?
        """
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        
        if row:
            fileUsed=row[0]
            return{"success":True,"exists":True,"fileUsed":fileUsed}
        else:
            return{"success":True,"exists":False}
    except Exception as e:
        print(f"Error checking file: {e}")
        return {"success": False,"error": "Failed to check the existing of the file."}
    finally:
        # Ensure the cursor and connection are always closed properly
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)  
            
async def handle_generate_recovery_file(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    password=request.get("password")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="""INSERT INTO Recovery_Key_Ring(SessionKey, UserEmail)
            VALUES (?, ?)
        """
        await cursor.execute(query, (password,email))
        
        query="DELETE FROM Recovery_Key_Ring WHERE Used = ? AND UserEmail=?"
        await cursor.execute(query, (True,email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("RECOVERY FILE"),email)
        
        await connection.commit() 
        return {"success": True}
    except Exception as e:
        print(f"Error adding recovery file: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("RECOVERY FILE FAILED"),email)
        await connection.commit()
        return {"success": False, "error": "Failed to add recovery file."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)    
                           
async def handle_delete_recovery_file(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        query="DELETE FROM Recovery_Key_Ring WHERE UserEmail = ?"
        
        await cursor.execute(query, (email,))
        await connection.commit()
        
        return {"success": True}
    except Exception as e:
        print(f"Error deleting recovery file: {e}")
        return {"success": False,"error": "Failed to delete recovery file."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_set_new_password(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    private_key=request.get("private_key")
    public_key=request.get("public_key")
    hahsed_password=request.get("hashed_password")
    timestamp=request.get("timestamp")
    key_id=request.get("key_id")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="UPDATE Users SET Password_User = ?, Flag_Reset = ? WHERE Email = ?"
        await cursor.execute(query, (hahsed_password,True,email))
        
        timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        query = """
                INSERT INTO Public_Key_Ring (Timestamp, KeyId, Public_Key, UserEmail)
                VALUES (?, ?, ?, ?)
            """
        await cursor.execute(query,(timestamp,key_id,public_key,email))
        
        query = """
                INSERT INTO Private_Key_Ring (Timestamp, KeyId, Private_Key, UserEmail, Public_Key)
                VALUES (?, ?, ?, ?, ?)
            """
        await cursor.execute(query,(timestamp,key_id,private_key,email,public_key))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("SET NEW PASSWORD"),email)
        
        await connection.commit()
        
        return {"success": True}

    except Exception as e:
        print(f"Error for forgotten password: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("SET NEW PASSWORD FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed for forgotten password."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_check_status(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        query="SELECT Flag_Reset FROM Users WHERE Email = ?"
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        
        if row:
            flag=row[0]
            return{"success":True,"exists":True,"Flag_Reset":flag}
        else:    
            return{"success":False,"error":"Error checking flag reset!!!"}

    except Exception as e:
        print(f"Error checking status: {e}")
        return {"success": False,"error": "Failed to check status."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)

async def handle_get_key_for_recovery(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        query="SELECT SessionKey FROM Recovery_Key_Ring WHERE UserEmail = ? AND Used = ?"
        await cursor.execute(query, (email,False))
        row = await cursor.fetchone()
        if row:
            sessionKey=row[0]
            query="UPDATE Recovery_Key_Ring SET Used = ? WHERE UserEmail = ?"
            await cursor.execute(query, (True,email,))
            await connection.commit()
            return{"success":True,"exists":True,"key":sessionKey}
        else:    
            return{"success":False,"error":"Error retriving session key!!!"}

    except Exception as e:
        print(f"Error for Session Key for Recovery: {e}")
        return {"success": False,"error": "Failed for Session Key for Recovery."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)

async def handle_recover_all_keys(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    rencKeys=request.get("rencKeys")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        query="UPDATE Users SET Flag_Reset = ? WHERE Email = ?"
        await cursor.execute(query, (False,email))
        for item in rencKeys:
            key_id = item.get("KeyId")
            encrypted_key = item.get("EncryptedKey")

            if not key_id or not encrypted_key:
                continue  # Skip invalid items

            # Update the EncryptedKey where KeyId matches for the given email
            await cursor.execute("""
                UPDATE Private_Key_Ring 
                SET Private_Key = ? 
                WHERE KeyId = ? AND UserEmail = ?
            """, (encrypted_key, key_id, email))

        await connection.commit()
        return {"success": True, "message": "Keys successfully updated"}
  
    except Exception as e:
        print(f"Error for recovering the keys: {e}")
        return {"success": False,"error": "Failed to recover the keys."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_update_2fa(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    # homomorphic=request.get("homomorphic")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="UPDATE Users SET TwoFactor = ? WHERE Email = ?"
        await cursor.execute(query, (True,email))
        # i have to get the last key's ID
        query = """
            SELECT TOP 1 KeyId 
            FROM Public_Key_Ring 
            WHERE UserEmail = ? 
            AND ExpirationDate >= GETDATE()
            ORDER BY Timestamp DESC;
        """        
        await cursor.execute(query, (email))
        row = await cursor.fetchone()
        if row:
            key_id = row[0]
            # print(key_id)
        else:
            return {"success": False,"error": "User not found"}
        query="INSERT TwoFactorInfo (UserEmail, KeysId) VALUES (?, ?)"
        await cursor.execute(query, (email,key_id))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("2FA UPDATE"),email)
       
        await connection.commit()
        return {"success": True}
    except Exception as e:
        print(f"Error updating 2FA status: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("2FA UPDATE FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to update 2FA status."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_2fa_info(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        # i have to get the last key's ID
        query="SELECT KeysId FROM TwoFactorInfo WHERE UserEmail = ?"
        await cursor.execute(query, (email))
        row = await cursor.fetchone()
        if row:
            key_id = row[0]
            # print(key_id)
            query="SELECT Public_Key, Private_Key FROM Private_Key_Ring WHERE UserEmail = ? AND keyId=?"
            await cursor.execute(query, (email,key_id))
            row = await cursor.fetchone()
        # !!! aici TREBUIE SA IAU ULTIMA CHEIE PRIVATA SI ULTIMA CHEIE PUBLICA !!!!
            if row:
                public_key, private_key = row
                query="SELECT PublicKeyMobile FROM MobileAppCredentials WHERE UserEmail = ?"
                await cursor.execute(query, (email))
                public_key_mobile = await cursor.fetchone()
                if public_key_mobile:
                    public_key_mobile = public_key_mobile[0]
                    # print(public_key_mobile)
                else:
                    public_key_mobile = None
                row = await cursor.fetchone()
                return {"success": True,"PublicKey": public_key,"PrivateKey": private_key,"PublicKeyMobile": public_key_mobile}
            else:
                return {"success": False,"error": "User not found"}
    except Exception as e:
        print(f"Error retrieving 2FA keys: {e}")
        return {"success": False,"error": "Failed to retrieve 2FA keys."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_save_mobile_data(db,request):
    connection = None
    cursor = None
    email=request.get("email")
    ownerEmail=request.get("ownerEmail")
    publicKey=request.get("publicKey")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        # i'll first search to see if i accidentally have the same email in the database
        query="SELECT UserEmail FROM MobileAppCredentials WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        row = await cursor.fetchone()
        if row:
            query="UPDATE MobileAppCredentials SET PublicKeyMobile = ? WHERE UserEmail = ?"
            await cursor.execute(query, (publicKey,email))
        else:
            query="INSERT INTO MobileAppCredentials (UserEmail, EmailAccount, PublicKeyMobile) VALUES (?, ?, ?)"
            await cursor.execute(query, (email,ownerEmail,publicKey))
        await connection.commit()
        
        return {"success": True}

    except Exception as e:
        print(f"Error saving mobile data: {e}")
        return {"success": False,"error": "Failed to save mobile data."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_mark_email_read(db,request):
    connection = None
    cursor = None
    email_id = request.get("email_id")
    sender=request.get("sender")
    myemail=request.get("email")
    receiver=request.get("receiver")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        if sender==myemail:
            query = "UPDATE EmailsSent SET IsRead = ? WHERE EmailSentId = ?"
            await cursor.execute(query, (1, email_id))
        if myemail==receiver:
            query = "UPDATE EmailsReceived SET IsRead = ? WHERE EmailReceivedId = ?"
            await cursor.execute(query, (1, email_id))
        
        await connection.commit()
        return {"success": True}

    except Exception as e:
        print(f"Error marking email as read: {e}")
        return {"success": False,"error": "Failed to mark email as read."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_mark_email_unread(db,request):
    connection = None
    cursor = None
    email_id = request.get("email_id")
    sender=request.get("sender")
    myemail=request.get("email")
    receiver=request.get("receiver")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        if sender==myemail:
            query = "UPDATE EmailsSent SET IsRead = ? WHERE EmailSentId = ?"
            await cursor.execute(query, (0, email_id))
        if myemail==receiver:
            query = "UPDATE EmailsReceived SET IsRead = ? WHERE EmailReceivedId = ?"
            await cursor.execute(query, (0, email_id))
        
        await connection.commit()
        return {"success": True}

    except Exception as e:
        print(f"Error marking email as unread: {e}")
        return {"success": False,"error": "Failed to mark email as unread."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_add_contact(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    contact_email=request.get("contact_email")
    
    print(f"Adding contact: {contact_email} for user: {email}")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        # Check if the contact already exists in the Contacts table
        query="SELECT * FROM Contacts WHERE Contact_Mail = ? AND ContactOwner = ?"
        await cursor.execute(query, (contact_email,email))
        row = await cursor.fetchone()
        if row:
            query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query,("CONTACT ADD FAILED"),email)
            await connection.commit()
            return {"success": False,"error": "Contact already exists"}
        
        query="SELECT Full_Name FROM Users WHERE Email = ?"
        await cursor.execute(query, (contact_email,))
        row = await cursor.fetchone()
        fullName=row[0]
        if not row:
            query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
            await cursor.execute(query,("CONTACT ADD FAILED"),email)
            await connection.commit()
            return {"success": False,"error": "User not found"}
        # Insert the contact into the Contacts table
        query="INSERT INTO Contacts (Contact_Mail, ContactOwner, ContactName) VALUES (?, ?, ?)"
        await cursor.execute(query, (contact_email,email,fullName))
        
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("CONTACT ADDED"),email)
   
        await connection.commit()
        
        return {"success": True}

    except Exception as e:
        print(f"Error adding contact: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("CONTACT ADD FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to add contact."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_contacts(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="SELECT ContactId, Contact_Mail, ContactName FROM Contacts WHERE ContactOwner = ?"
        await cursor.execute(query, (email,))
        rows = await cursor.fetchall()
        
        contacts = [{"Id": row[0], "Contact_Mail": row[1], "ContactName": row[2]} for row in rows]
        
        return {"success": True,"contacts": contacts}

    except Exception as e:
        print(f"Error retrieving contacts: {e}")
        return {"success": False,"error": "Failed to retrieve contacts."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_delete_contact(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    contact_email=request.get("contact_email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="DELETE FROM Contacts WHERE Contact_Mail = ? AND ContactOwner = ?"
        await cursor.execute(query, (contact_email,email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("CONTACT DELETED"),email)
        
        await connection.commit()
        
        return {"success": True}

    except Exception as e:
        print(f"Error deleting contact: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("CONTACT DELETE FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to delete contact."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_add_folder(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    folder_name=request.get("folder_name")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        # Check if the folder already exists in the Folders table
        query="SELECT * FROM Folders WHERE FolderName = ? AND OwnerFolder = ?"
        await cursor.execute(query, (folder_name,email))
        row = await cursor.fetchone()
        if row:
            return {"success": False,"error": "Folder already exists"}
        
        # Insert the folder into the Folders table
        query="INSERT INTO Folders (FolderName, OwnerFolder) VALUES (?, ?)"
        await cursor.execute(query, (folder_name,email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("FOLDER ADDED"),email)
        
        await connection.commit()
        
        return {"success": True}

    except Exception as e:
        print(f"Error adding folder: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("FOLDER ADD FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to add folder."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_folders(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="SELECT FolderId, FolderName FROM Folders WHERE OwnerFolder = ?"
        await cursor.execute(query, (email,))
        rows = await cursor.fetchall()
        
        folders = [{"Id": row[0], "FolderName": row[1]} for row in rows]
        
        return {"success": True,"folders": folders}

    except Exception as e:
        print(f"Error retrieving folders: {e}")
        return {"success": False,"error": "Failed to retrieve folders."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_delete_folder(db,request):
    connection = None
    cursor = None
    email = request.get("email")
    folder_name=request.get("folder_name")
    
    try:
        connection = await db.get_connection()  
        cursor = await connection.cursor()
        
        query="SELECT EmailSentId FROM EmailsSent WHERE Folder = ? AND Sender = ?"
        await cursor.execute(query, (folder_name,email))
        rows = await cursor.fetchall()
        emails_sent_ids=[]
        for row in rows:
            emails_sent_ids = [row[0] for row in rows]
        
        query="SELECT EmailReceivedId FROM EmailsReceived WHERE Folder = ? AND Receiver = ?"
        await cursor.execute(query, (folder_name,email))
        rows = await cursor.fetchall()
        emails_received_ids=[]
        for row in rows:
            emails_received_ids = [row[0] for row in rows]
            
        query="DELETE FROM EmailsSent WHERE Folder = ? AND Sender = ?"
        await cursor.execute(query, (folder_name,email))
        
        query="DELETE FROM EmailsReceived WHERE Folder = ? AND Receiver = ?"
        await cursor.execute(query, (folder_name,email))
        
        query="DELETE FROM Folders WHERE FolderName = ? AND OwnerFolder = ?"
        await cursor.execute(query, (folder_name,email))
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("DELETE FOLDER"),email)
        
        await connection.commit()
        
        return {"success": True, "emails_sent_ids": emails_sent_ids, "emails_received_ids": emails_received_ids}

    except Exception as e:
        print(f"Error deleting folder: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("DELETE FOLDER FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to delete folder."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_admin_info(db,request):
    connection=None
    cursor = None
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="SELECT COUNT(*) FROM Users"
        await cursor.execute(query)
        row = await cursor.fetchone()
        total_users = row[0]

        
        query="SELECT COUNT(*) FROM EmailsSent"
        await cursor.execute(query)
        row = await cursor.fetchone()
        total_sent_emails = row[0]
        
        query="SELECT COUNT(*) FROM Users WHERE TwoFactor = ?"
        await cursor.execute(query, (True,))
        row = await cursor.fetchone()
        total_2fa_users = row[0]
        
        query = """
        WITH Months AS (
            SELECT 1 AS MonthNumber, 'January' AS MonthName
            UNION SELECT 2, 'February'
            UNION SELECT 3, 'March'
            UNION SELECT 4, 'April'
            UNION SELECT 5, 'May'
            UNION SELECT 6, 'June'
            UNION SELECT 7, 'July'
            UNION SELECT 8, 'August'
            UNION SELECT 9, 'September'
            UNION SELECT 10, 'October'
            UNION SELECT 11, 'November'
            UNION SELECT 12, 'December'
        )
        SELECT 
            m.MonthNumber,
            COUNT(l.LogId) AS RegistrationCount
        FROM Months m
        LEFT JOIN Logs l
            ON MONTH(l.TimestampLog) = m.MonthNumber
            AND YEAR(l.TimestampLog) = 2025
            AND l.ActionName = 'REGISTER'
        GROUP BY 
            m.MonthNumber
        ORDER BY 
            m.MonthNumber;
        """
        await cursor.execute(query)

        # Fetch all results
        rows = await cursor.fetchall()

        # Create an array of 12 numbers (one for each month)
        user_data = [0] * 12  # Initialize with zeros for all months
        for row in rows:
            month_number = row[0]  # MonthNumber (1 to 12)
            count = row[1]  # RegistrationCount
            user_data[month_number - 1] = count  # Adjust for zero-based index

        print(user_data)
        
        return {"success": True,"total_users": total_users,"total_sent_emails": total_sent_emails,"total_2fa_users": total_2fa_users,"user_data": user_data}
    except Exception as e:
        print(f"Error retrieving admin info: {e}")
        return {"success": False,"error": "Failed to retrieve admin info."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
    
async def handle_get_admin_logs(db, request):
    connection = None
    cursor = None
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        # Modified query to split TimestampLog into date and time
        query = """
        SELECT 
            ActionName, 
            UserEmail, 
            CAST(TimestampLog AS DATE) AS LogDate, 
            CONVERT(VARCHAR(8), TimestampLog, 108) AS LogTime
        FROM Logs
        """
        await cursor.execute(query)
        rows = await cursor.fetchall()
        
        # Map the results to a list of dictionaries
        logs = [
            {
                "ActionName": row[0],
                "UserEmail": row[1],
                "LogDate": str(row[2]),  
                "LogTime": row[3]       
            }
            for row in rows
        ]
        
        return {"success": True, "logs": logs}
    
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return {"success": False, "error": "Failed to retrieve logs."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_admin_users(db, request):
    connection = None
    cursor = None
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query = """
        SELECT 
            Email, 
            Full_Name,
            TwoFactor
        FROM Users
        """
        await cursor.execute(query)
        rows = await cursor.fetchall()
        
        # Map the results to a list of dictionaries
        users = [
            {
                "email": row[0],
                "fullName": row[1], 
                "enabled": row[2] if row[2] is not None else False  # Default to False if None,
            }
            for row in rows
        ]
        
        return {"success": True, "users": users}
    
    except Exception as e:
        print(f"Error retrieving users: {e}")
        return {"success": False, "error": "Failed to retrieve users."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_disable_2fa(db, request):
    connection = None
    cursor = None
    email = request.get("user_email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="UPDATE Users SET TwoFactor = ? WHERE Email = ?"
        await cursor.execute(query, (False,email))
        
        query="DELETE FROM TwoFactorInfo WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        query="DELETE FROM MobileAppCredentials WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("2FA DISABLED"),email)
        
        await connection.commit()
        
        return {"success": True}
    
    except Exception as e:
        print(f"Error disabling 2FA: {e}")
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        await cursor.execute(query,("2FA DISABLED FAILED"),email)
        await connection.commit()
        return {"success": False,"error": "Failed to disable 2FA."}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_delete_user(db, request):
    connection = None
    cursor = None
    email = request.get("user_email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        # Delete the user's keys from the Private_Key_Ring and Public_Key_Ring tables
        query="DELETE FROM Private_Key_Ring WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        # query="DELETE FROM Public_Key_Ring WHERE UserEmail = ?"
        # await cursor.execute(query, (email,))   
        
        query="DELETE FROM Recovery_Key_Ring WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        query="SELECT EmailSentId FROM EmailsSent WHERE Sender = ?"
        await cursor.execute(query, (email,))
        rows = await cursor.fetchall()
        emails_sent_ids = [row[0] for row in rows]
        
        query="SELECT EmailReceivedId FROM EmailsReceived WHERE Receiver = ?"
        await cursor.execute(query, (email,)) 
        rows = await cursor.fetchall()
        emails_received_ids = [row[0] for row in rows]
        
        query="DELETE FROM EmailsReceived WHERE Receiver = ?"
        await cursor.execute(query, (email))
        
        query="DELETE FROM EmailsSent WHERE Sender = ?"
        await cursor.execute(query, (email))
        
        # Delete the user's contacts from Contacts table
        query="DELETE FROM Contacts WHERE ContactOwner = ?"
        await cursor.execute(query, (email,))
        
        # Delete the user's folders from Folders table
        query="DELETE FROM Folders WHERE OwnerFolder = ?"
        await cursor.execute(query, (email,))
        
        # Delete the user's 2FA info from TwoFactorInfo and MobileAppCredentials tables
        query="DELETE FROM TwoFactorInfo WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        query="DELETE FROM MobileAppCredentials WHERE UserEmail = ?"
        await cursor.execute(query, (email,))

        query="DELETE FROM Recovery_Credentials WHERE UserEmail = ?"
        await cursor.execute(query, (email,))
        
        query="DELETE FROM Users WHERE Email = ?"
        await cursor.execute(query, (email,))
        
        query="INSERT INTO Logs(ActionName, UserEmail) VALUES (?, ?)"
        cursor.execute(query,("USER DELETED"),email)
        
        await connection.commit()
        
        return {"success": True, "deleted_emails_sent_ids": emails_sent_ids, "deleted_emails_received_ids": emails_received_ids}
    except Exception as e:
        print(f"Error deleting user: {e}")
        return {"success": False,"error": "Error deleting user"}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
            
async def handle_get_2fa_state(db, request):
    connection = None
    cursor = None
    email = request.get("email")
    
    try:
        connection = await db.get_connection()
        cursor = await connection.cursor()
        
        query="SELECT TwoFactor FROM Users WHERE Email=?"
        await cursor.execute(query,(email,))
        row = await cursor.fetchone()
        TwoFactor=row[0]
        
        if TwoFactor:
            return {"success":True, "2fa":TwoFactor}
        else:
            return {"success":False,"error":"Error at gettinf 2FA"}
    except Exception as e:
        print(f"Error getting 2FA: {e}")
        return {"success": False,"error": "Error getting 2FA"}
    finally:
        if cursor:
            await cursor.close()
        if connection:
            await db.pool.release(connection)
        