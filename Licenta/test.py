from websocket import create_connection
ws = create_connection("wss://cryptmail.stud.fsisc.ro/mobile/")
print("Connected")
ws.send("Hello")
print(ws.recv())
ws.close()
