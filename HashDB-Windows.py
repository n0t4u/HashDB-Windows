# -*- coding: utf-8 -*-

#To Do
#Eliminado de duplicados --> Coger los duplicados de la tabla y ver si siguen existiendo en la ruta especificada. Si no borrar. Volver a preguntar por duplicados. --> os.path.exists() está dando un error, comprobar argumento pasado
#Corregir error en buscar fichero por hash
#Sentencia SQL Hash repetidos no funciona

#Imports
import logging
import os
import sys
import platform
import re
import sqlite3
try:
	import readline
except:
	pass
import subprocess
from datetime import datetime
from terminaltables import AsciiTable
import time
import concurrent.futures as futures
import threading

#Variables
so =""
scanDate=""
"""config={
	"workers":10,
	"timeout":0,
	"verbose":0
}"""
config={}
system ={"Windows":{
			"clear":"cls",
			"md5":'CertUtil -hashfile PATH MD5 | find /v "hash"',
			"sha1":'CertUtil -hashfile PATH SHA1 | find /v "hash"',
			"sha256":'CertUtil -hashfile PATH SHA256 | find /v "hash"'},
		"Linux":{
			"clear":"clear",
			"md5":"md5sum PATH | grep -o  '^[[:xdigit:]]*'",
			"sha1":"sha1sum PATH | grep -o  '^[[:xdigit:]]*'",
			"sha256":"sha256sum PATH | grep -o  '^[[:xdigit:]]*'"
		}}
tables =[]
selectedTable =""
paths=[]


#Functions
#Cabecera de la aplicación
def header():
	print("""
	     _    __          _     _____  ____  
	    | |  |  /        | |   |  __ \|  _ \ 
	    | |__| | __ _ ___| |__ | |  | | |_) |
	    |  __  |/ _` / __| '_ \| |  | |  _ < 
	    | |  | | (_| \__ \ | | | |__| | |_) |
	   /__|  |__\__,_|___/_| | |_____/|____/ 
	                         | |             
	           This is n0t4u |_|             
""")

#Detección del SO y obtención de la fecha 
def setup():
	global so,scanDate
	createDatabase()
	getConfig()
	if config["verbose"]:
		logging.basicConfig(level=logging.INFO)
	so =platform.system()
	scanDate =datetime.today().strftime("%Y-%m-%d")

#Menú principal de la aplicación
def mainMenu():
	print("""HashDB
	[0] Mostrar tablas de datos
	[1] Seleccionar tabla de datos
	[2] Crear nueva tabla de datos
	[3] Borrar tabla de datos
	[4] Calcular hashes
	[5] Mostrar resultados
	[6] Buscar hashes repetidos
	[7] Buscar fichero por hash
	[8] Exportar resultados
	[9] Eliminar entradas repetidas
	[10] Cambiar la configuración del programa
	[99] Salir del programa
		""")
	option = input("Seleccione una opción:\n» ")
	if re.search(r'^\d',option) and int(option) >= 0 and int(option) <100:
		option = int(option)
		if option ==0:
			showTables()
		elif option ==1:
			selectTable()
		elif option ==2:
			createTable()
		elif option ==3:
			deleteTable()
		elif option ==4:
			calculateHashes()
		elif option ==5:
			showHashes()
		elif option ==6:
			checkHashes()
		elif option ==7:
			findHash()
		elif option ==8:
			exportResults()
		elif option	==9:
			deleteHashes()
		elif option ==10:
			changeConfiguration()
		elif option ==99:
			sys.exit(0)
		else:
			mainMenu()
	else:
		print("[!] Debe introducir una opción válida.")
		return

#Creación de la base de datos si no existe
def createDatabase():
	try:
		connection = sqlite3.connect("HashDB.db")
		c = connection.cursor()
		print("[INFO] Conectado a la base de datos de HashDB.")
		getTables(c)
	except:
		print("[!] No se ha podido conectar a la base de datos de HashDB.")
	else:
		try:
			createSetupTableQuery="""CREATE TABLE IF NOT EXISTS setup ( 
				option VARCHAR(64) PRIMARY KEY,
				value INTEGER NOT NULL
				);"""
			insertSetupOptionsQuery="""INSERT INTO setup (option,value) VALUES ("workers",10),("timeout",0),("verbose",0)"""
			c.execute(createSetupTableQuery)
			c.execute(insertSetupOptionsQuery)
			connection.commit()
		except Exception as e:
			if not re.search(r'UNIQUE',str(e)):
				raise(e)
	finally:
		c.close()
		connection.close()

#Creación de una tabla de datos
def createTable():
	print("Indique el nombre de la nueva tabla de datos:")
	tablename = input("» ")
	"""try:
					tables.index(tablename)
					print("[!] Ya existe una tabla con ese nombre.")
					return
				except Exception as e:
					print(e)
					#pass"""
	if tablename in tables:
		print("[!] Ya existe una tabla con ese nombre.")
		return

	if tablename =="q" or tablename =="quit":
		return
	elif tablename=="setup" or tablename =="sqlite_sequence" or tablename =="sqlite sequence":
		print("[!] Nombres no permitidos")
		return
	elif not re.search(r'[^0-9A-Za-z\-\_\ ]',tablename):
		if re.search(r'^[0-9]',tablename):
			print("[!] El nombre de la tabla no puede comenzar por un número")
			return
		tablename = re.sub(" ","_",tablename)
		createTableQuery = """CREATE TABLE IF NOT EXISTS """+tablename+""" (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			filepath VARCHAR(512) NOT NULL UNIQUE,
			filename VARCHAR(128) NOT NULL,
			scanDate DATE NOT NULL,
			md5 CHAR(32),
			sha1 CHAR(40),
			sha256 CHAR(64)
			);""" 
		try:
			connection = sqlite3.connect("HashDB.db")
			c = connection.cursor()
			c.execute(createTableQuery)
			connection.commit()
			getTables(c)
			print("[*] Tabla %s creada correctamente." %tablename)
			#print("Pulse cualquier tecla para continuar.")
			#input("» ")
		except Exception as e:
			raise e
			#print("[!] No se ha podido crear la tabla de datos %s" %tablename)
		else:
			c.close()
			connection.close()			
		finally:
			return
	else:
		print("[!] Debe introducir un nombre válido. Sólo se permiten caracteres alfanuméricos, '-' y '_'")
		return
		#print("Pulse cualquier tecla para continuar.")
		#input("» ")

#Elimina una tabla de datos
def deleteTable():
	if not tables:
		print("[INFO] No existe ninguna tabla de datos.")
		return False
	print("\nSeleccione una tabla:")
	for i in range(len(tables)):
		print("[%d] %s" %(i,tables[i]))
	selected = input("» ")
	if re.search(r"\d",selected) and int(selected) >= 0 and int(selected) < len(tables):
		deleteTableQuery="DROP TABLE "+tables[int(selected)]
		try:
			connection = sqlite3.connect("HashDB.db")
			c = connection.cursor()
			#print(deleteTableQuery)
			c.execute(deleteTableQuery)
			connection.commit()
			print("Tabla %s eliminada correctamente" %tables[int(selected)])
		except Exception as e:
			raise e
		else:
			getTables(c)
			c.close()
			connection.close()
		finally:
			return
#Obtiene las tablas existentes en la base de datos
def getTables(c):
	getTablesQuery ="""
	SELECT name FROM sqlite_master
	WHERE type='table'
	ORDER BY name;
	"""
	try:
		tables.clear()
		c.execute(getTablesQuery)
		for row in c.fetchall():
			if row[0]=="sqlite_sequence" or row[0]=="setup":
				continue
			else:
				tables.append(row[0])
	except Exception as e:
		raise e
	finally:
		return

#Muestra las tablas para poder elegir entre las existentes
def selectTable():
	if not tables:
		print("[INFO] No existe ninguna tabla de datos.")
		return False
	print("\nSeleccione una tabla:")
	for i in range(len(tables)):
		print("[%d] %s" %(i,tables[i]))
	selected = input("» ")
	if re.search(r"\d",selected) and int(selected) >= 0 and int(selected) < len(tables):
		global selectedTable
		selectedTable = tables[int(selected)]
		print("Se ha seleccionado la tabla %s" %selectedTable)
		#print("Pulse cualquier tecla para continuar.")
		#input("» ")
		return True
	elif selected == "q":
		print("Volviendo al menú principal")
		return
	else:
		print("[!] La tabla que indica no existe.\n")
		selectTable()
	
#Muestra todas las tablas existentes y la tabla seleccionada actualmente
def showTables():
	#sprint(selectedTable)
	for t in tables:
		if t ==selectedTable:
			print("\t[*] %s" %t)
		else:
			print("\t[ ] %s" %t)
	#print("\nPulse cualquier tecla para continuar.")
	#input("» ")

#Insercción de valores en la tabla de datos seleccionada
#def insertValues(filepath,filename,md5,sha1,sha256,tablename=selectedTable,scanDate=date):
def insertValues(c,filepath,filename,md5,sha1,sha256):
	insertValuesQuery="""INSERT INTO """+selectedTable+""" (filepath,filename,scanDate,md5,sha1,sha256) VALUES (?,?,?,?,?,?)
	"""
	try:
		#connection = sqlite3.connect("HashDB.db")
		#c = connection.cursor()
		c.execute(insertValuesQuery,[filepath,filename,scanDate,md5,sha1,sha256])
		#connection.commit()
	except Exception as e:
		if re.search(r'UNIQUE[\S\s]*\.filepath',str(e)):
			updateValues(filepath,filename,md5,sha1,sha256)
		else:
			print("[ERROR]",e)
		return
	else:
		#c.close()
		#connection.close()
		#print("Insertados los valores")
		return

#Actualización de valores cuando la entrada ya existe
def updateValues(filepath,filename,md5,sha1,sha256):
	insertValuesQuery="""UPDATE"""+selectedTable+"""
	SET scanDate = ?,md5= ?,sha1 = ?,sha256 =? 
	WHERE filepath LIKE ?;
	"""
	try:
		#connection = sqlite3.connect("HashDB.db")
		#c = connection.cursor()
		c.execute(insertValuesQuery,[scanDate,md5,sha1,sha256,filepath])
		#connection.commit()
	except Exception as e:
		raise e
	finally:
		return

#Menú para la generación de Hashes
def calculateHashes():
	if not selectedTable:
		print("[!] No ha seleccionado ninguna tabla.")
		selected= selectTable()
		if not selected:
			return
	print("Indique la ruta completa del directorio raíz.")
	root = input("» ")
	if not re.search(r'[^0-9A-Za-záéíóú\s\.\:\_\-\\\/]',root):
		print("""Indique los algoritmos hash que quiere calcular:
	[0] md5
	[1] sha1
	[2] sha256

Puede indicar varios algoritmos a la vez. Ejemplo: 01
		""")
		hashAlg = input("» ")
		startTime = time.time()
		iterateDirectories(root)
		if re.search(r'(012|021|102|120|201|210)', hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateAll,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes md5,sha1 y sha256 completado.")
		elif re.search(r'(01|10)',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateMD5SHA1,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes md5 y sha1 completado.")
		elif re.search(r'(02|20)',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateMD5SHA256,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes md5 y sha256 completado.")
		elif re.search(r'(12|21)',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateSHA,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes sha1 y sha256 completado.")
		elif re.search(r'0',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					"""threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateMD5,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()"""
					c = connection.cursor()
					calculateMD5(c)
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes md5 completado.")
		elif re.search(r'1',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateSHA1,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes SHA1 completado.")
		elif re.search(r'2',hashAlg):
			try:
				connection = sqlite3.connect("HashDB.db", check_same_thread=False)
			except Exception as e:
				raise e
			else:
				try:
					threads=[]
					for i in range(config["workers"]):
						c = connection.cursor()
						thread= threading.Thread(target=calculateSHA256,args=(c,),name=i,daemon=True)
						thread.start()
						threads.append(thread)

					for thread in threads:
						thread.join()
				except Exception as e:
					raise e
				else:
					connection.commit()
					connection.close()
					print("\nCálculo de hashes SHA256 completado.")
		else:
			print("[!] Error al introducir el tipo de algoritmo, volviendo al menún principal.")
			#print("Pulse cualquier tecla para continuar.")
			#input("» ")
			return
		executionTime = time.time()- startTime
		if executionTime/60 > 1:
			print("--- %d segundos --- (%d minutos) ---" %(round(executionTime,3), round(executionTime/60,3)))
		else:
			print("--- %d segundos ---" %round(executionTime,3))
	else:
		print("[!] Debe introducir una ruta válida.")
		calculateHashes()

#Recorrido de los directorios y subdirectorios para el cálculo de los hashes
def iterateDirectories(root):
	"""with futures.ThreadPoolExecutor(max_workers=4) as executor:
				with os.scandir() as scanner:
					results = executor.map(iterateDirectory0,[file for file in scanner])"""
	try:
		for subdir, dirs, files in os.walk(root):
			for filename in files:
				filepath = '"'+subdir + os.sep + filename+'"'
				#filepath = re.sub(r"\'",r"\\'",filepath)
				#filepath = re.sub(r"\(",r"\\(",filepath)
				#filepath = re.sub(r"\)",r"\\)",filepath)
				#filepath = re.sub(r" ",r"\/ ",filepath)
				paths.append(filepath)
	except Exception as e:
		raise e
	else:
		print("Detectados %d archivos" %len(paths))
		return

def getCurrentPath():
	global paths
	#self.lock.acquire()
	return paths.pop()
	#self.lock.release()

def calculateAll(c):
	for path in paths:
		filepath = getCurrentPath()
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		print(filename, filepath)

		md5 = md5checksum(filepath,filename)
		sha1 = sha1checksum(filepath,filename)
		sha256 =sha256checksum(filepath,filename)
		insertValues(c,filepath.strip('"'),filename.strip('"'),md5,sha1,sha256)

def calculateMD5SHA1(c):
	for path in paths:
		filepath = getCurrentPath()
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		print(threading.currentThread().getName(), filename, filepath)

		md5 = md5checksum(filepath,filename)
		sha1 = sha1checksum(filepath,filename)
		sha256 =""
		insertValues(c,filepath,filename,md5,sha1,sha256)

def calculateMD5SHA256(c):
	for path in paths:
		filepath = getCurrentPath()
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		print(threading.currentThread().getName(), filename, filepath)

		md5 = md5checksum(filepath,filename)
		sha1 = ""
		sha256 =sha256checksum(filepath,filename)
		insertValues(c,filepath,filename,md5,sha1,sha256)

def calculateSHA(c):
	for path in paths:
		filepath = getCurrentPath()
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		print(threading.currentThread().getName(), filename, filepath)
		md5 = ""
		sha1 = sha1checksum(filepath,filename)
		sha256 =sha256checksum(filepath,filename)
		insertValues(c,filepath,filename,md5,sha1,sha256)

def calculateSHA1(c):
	for path in paths:
		filepath = getCurrentPath()
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		print(threading.currentThread().getName(), filename, filepath)

		md5 = ""
		sha1 = sha1checksum(filepath,filename)
		sha256 = ""
		insertValues(filepath,filename,md5,sha1,sha256)

	print("\nCálculo de hashes sha1 y completado.")

def calculateMD5(c):
	#with futures.ThreadPoolExecutor(max_workers=setup.workers) as executor:
	
	for path in paths:
		filepath = getCurrentPath()
		#filename = re.split(os.sep,filepath)[-1]
		filename = filepath.rsplit(os.sep,1)[1]
		filename = filename.rstrip('"')
		#print(threading.currentThread().getName(), filename, filepath)
		print(filename,filepath)

		md5 = md5checksum(filepath,filename)
		sha1 = ""
		sha256 =""
		insertValues(c,filepath,filename,md5,sha1,sha256)
		#sys.stdout.write(filepath)
		#sys.stdout.flush()
		#n +=1

def calculateSHA256(c):

	for path in paths:
		filepath = getCurrentPath()
		filename = re.split(os.sep,filepath)[-1]
		filename = filename.rstrip('"')
		print(threading.currentThread().getName(), filename, filepath)

		md5 = ""
		sha1 = ""
		sha256 =sha256checksum(filepath,filename)
		insertValues(c,filepath,filename,md5,sha1,sha256)

#Cálculo del md5 de un fichero
def md5checksum(filepath,filename):
	command =system[so]["md5"]
	command =command.replace("PATH",filepath)
	#print("COMMAND",command)
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	try:
		return p.communicate(timeout=15+config["timeout"])[0].decode('utf-8').rstrip("\r\n")
	except:
		print("[!] No se ha podido calcular el md5 del fichero %s" %filename)
		return
	
#Cálculo del SHA1 de un fichero
def sha1checksum(filepath,filename):
	command =system[so]["sha1"]
	command =command.replace("PATH",filepath)
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	try:
		return p.communicate(timeout=20+config["timeout"])[0].decode('utf-8').rstrip("\r\n")
	except:
		print("[!] No se ha podido calcular el sha1 del fichero %s" %filename)
		return

#Cálculo del SHA256 de un fichero
def sha256checksum(filepath,filename):
	command =system[so]["sha256"]
	command =command.replace("PATH",filepath)
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	try:
		return p.communicate(timeout=25+config["timeout"])[0].decode('utf-8').rstrip("\r\n")
	except:
		print("[!] No se ha podido calcular el sha256 del fichero %s" %filename)
		return

#Muestra los hashes de la tabla de datos de forma paginada
def showHashes():
	if not selectedTable:
		print("[!] No ha seleccionado ninguna tabla.")
		selected= selectTable()
		if not selected:
			return
	print("Indique el número de resultados a mostrar a la vez")
	try:
		count = int(input("» "))
	except:
		print("[!] Debe indicar una cantidad numérica.")
		return
	else:
		totalQuery = "SELECT COUNT(id) FROM "+selectedTable
		offset = 0
		try:
			connection=sqlite3.connect("HashDB.db")
			c = connection.cursor()
			c.execute(totalQuery)
			totalCount = c.fetchone()[0]
			#print(totalCount, type(totalCount))
		except Exception as e:
			raise e
		#while offset < totalCount-count:
		while offset < totalCount:
			selectHashesQuery = "SELECT * FROM " +selectedTable +" ORDER BY id LIMIT "+str(count) + " OFFSET "+ str(offset)
			#selectRegexHashesQuery = "SELECT * FROM " +selectedTable +"WHERE filepath REGEXP "+regex+" ORDER BY id LIMIT "+str(count) + " OFFSET "+ str(offset)
			try:
				datatable=[]
				datatable.append(["ID","Ruta","Nombre","Fecha","MD5","SHA1","SHA256"])
				c.execute(selectHashesQuery)
				for file in c.fetchall():
					datatable.append(file) 
				asciiTable = AsciiTable(datatable)
				print(asciiTable.table)
			except Exception as e:
				raise e
			else:				
				print("Mostrando resultados del %d al %d (Total: %d)" %(offset+1,offset+count,totalCount))
				offset += count
				if input("» ") =="q":
					return

		return

#Comprueba la existencia de hashes repetidos en la tabla de datos
def checkHashes():
	if not selectedTable:
		print("[!] No ha seleccionado ninguna tabla.")
		selected = selectTable()
		if not selected:
			return
	selectRepeatedQuery =("""SELECT filename AS filename, filepath AS filepath,scanDate AS scanDate, md5 AS md5, sha1 AS sha1, sha256 AS sha256 FROM """+selectedTable+""" WHERE md5 IN (SELECT md5 FROM """+selectedTable+""" WHERE md5 NOT LIKE "" GROUP BY md5 HAVING count(md5)>1) OR sha1 IN (SELECT sha1 FROM """+selectedTable+""" WHERE sha1 NOT LIKE "" GROUP BY sha1 HAVING count(sha1)>1) OR sha256 IN (SELECT sha256 FROM """+selectedTable+""" WHERE sha256 NOT LIKE "" GROUP BY sha256 HAVING count(sha256)>1) ORDER BY md5, sha1, sha256;
	""")
	try:
		connection = sqlite3.connect("HashDB.db")
		c = connection.cursor()
		c.execute(selectRepeatedQuery)
		datatable=[]
		datatable.append(["Nombre","Ruta","Fecha Escaneo","MD5","SHA1","SHA256"])
		for file in c.fetchall():
			datatable.append(file) 
		asciiTable = AsciiTable(datatable)
		print(asciiTable.table)
		c.close()
		connection.close()
	except Exception as e:
		print("ERROR", e)
		raise e
	finally:
		return

#Busca un hash dentro de la base de datos
def findHash():
	if not selectedTable:
		print("[!] No ha seleccionado ninguna tabla.")
		selected = selectTable()
		if not selected:
			return
	print("Indique el tipo de hash (md5, sha1, sha256, quit):")
	hashType = input("» ")
	if hashType == "quit" or hashType == "q":
		return
	elif hashType =="md5":
		print("Indique el hash:")
		hashValue= input("» ")
		if not re.search(r'[^0-9a-fA-F]',hashValue):
			findMD5Query = """SELECT filename AS filename, filepath AS filepath, md5 AS md5 FROM """+selectedTable+""" WHERE md5 LIKE ? ORDER BY filename"""
			try:
				connection=sqlite3.connect("HashDB.db")
				c = connection.cursor()
				c.execute(findMD5Query,(hashValue,))
				datatable=[]
				datatable.append(["Nombre","Ruta","MD5"])
				for file in c.fetchall():
					datatable.append(file) 
				asciiTable = AsciiTable(datatable)
				print(asciiTable.table)
				c.close()
				connection.close()
			except Exception as e:
				raise e
		else:
			print("[!] Debe introducir una cadena hexadecimal.")
			return
	elif hashType =="sha1":
		print("Indique el hash:")
		hashValue= input("» ")
		if not re.search(r'[^0-9a-fA-F]',hashValue):
			findMD5Query = """SELECT filename AS filename, filepath AS filepath, sha1 AS sha1 FROM """+selectedTable+""" WHERE sha1 LIKE ? ORDER BY filename"""
			try:
				connection=sqlite3.connect("HashDB.db")
				c = connection.cursor()
				c.execute(findMD5Query,(hashValue,))
				datatable=[]
				datatable.append(["Nombre","Ruta","SHA1"])
				for file in c.fetchall():
					datatable.append(file) 
				asciiTable = AsciiTable(datatable)
				print(asciiTable.table)
				c.close()
				connection.close()
			except Exception as e:
				raise e
		else:
			print("[!] Debe introducir una cadena hexadecimal.")
			return
	elif hashType =="sha256":
		print("Indique el hash:")
		hashValue= input("» ")
		if not re.search(r'[^0-9a-fA-F]',hashValue):
			findMD5Query = """SELECT filename AS filename, filepath AS filepath, sha256 AS sha256 FROM """+selectedTable+""" WHERE sha256 LIKE ? ORDER BY filename"""
			try:
				connection=sqlite3.connect("HashDB.db")
				c = connection.cursor()
				c.execute(findMD5Query,(hashValue,))
				datatable=[]
				datatable.append(["Nombre","Ruta","SHA256"])
				for file in c.fetchall():
					datatable.append(file) 
				asciiTable = AsciiTable(datatable)
				print(asciiTable.table)
				c.close()
				connection.close()
			except Exception as e:
				raise e
		else:
			print("[!] Debe introducir una cadena hexadecimal.")
			return
	else:
		print("[!] Debe indicar una opción válida")
		findHash()

#Exportar resultados obtenidos
def exportResults():
	print("Indique el nombre del fichero de salida: ")
	outfilename= input("» ")
	if len(outfilename)==0:
		outfilename = "HashDB_results"
	print("Los resultados se guardarán en el fichero %s" %outfilename)
	print("""Indique una opción de salida:
	[0] Exportar todo
	[1] Exportar tabla actual
	[2] Exportar repetidos
	[3] Exportar repetidos tabla actual""")
	exportType = input("» ")
	if re.search(r'^[\d]{1}',exportType) and int(exportType) >= 0 and int(exportType) <4:
		exportType = int(exportType)
		try:
			connection=sqlite3.connect("HashDB.db")
			c = connection.cursor()
		except Exception as e:
			raise e
		else:
			if exportType ==0:
				with open(outfilename+".csv","w",encoding="iso-8859-1") as file:
						file.write("Ruta,Nombre,Fecha,MD5,SHA1,SHA256;\n")
				file.close()
				for table in tables:
					selectAllQuery = "SELECT filepath,filename,scanDate,md5,sha1,sha256 FROM " +table +" ORDER BY id"
					logging.info(selectAllQuery)
					try:
						c.execute(selectAllQuery)
					except Exception as e:
						raise e
					try:
						with open(outfilename+".csv","a",encoding="iso-8859-1") as file:
							#logging.info(c.fetchall())
							data = c.fetchall()
							print(data)
							print(len(data))
							for line in data:
								print(line)
								res = line[0]+","+line[1]+","+line[2]+","+line[3]+","+line[4]+","+line[5]+";\n"
								file.write(res) 
							file.close()
						print("[INFO] Los datos fueron correctamente exportados al fichero %s.csv" %outfilename)
					except Exception as e:
						raise e
					finally:
						return
			elif exportType ==1:
				if not selectedTable:
					print("[!] No ha seleccionado ninguna tabla.")
					selected = selectTable()
					if not selected:
						return
				selectAllQuery = "SELECT id,filepath,filename,scanDate,md5,sha1,sha256 FROM " +selectedTable +" ORDER BY id"
				try:
					c.execute(selectAllQuery)
				except Exception as e:
					raise e
				try:
					with open(outfilename+".csv","w",encoding="iso-8859-1") as file:
						file.write("ID,Ruta,Nombre,Fecha,MD5,SHA1,SHA256;\n")
						for line in c.fetchall():
							print(line[5])
							res = line[0]+","+line[1]+","+line[2]+","+line[3]+","+line[4]+","+line[5]+";\n"
							file.write(res) 
						file.close()
					print("[INFO] Los datos fueron correctamente exportados al fichero %s.csv" %outfilename)
				except Exception as e:
					raise e
				finally:
					return
			elif exportType ==2:
				with open(outfilename+".csv","w",encoding="iso-8859-1") as file:
						file.write("ID,Ruta,Nombre,Fecha,MD5,SHA1,SHA256;\n")
				file.close()
				for table in tables:
					selectRepeatedQuery =("""SELECT id AS id, filename AS filename, filepath AS filepath,scanDate AS scanDate, md5 AS md5, sha1 AS sha1, sha256 AS sha256 FROM """+table+""" WHERE md5 IN (SELECT md5 FROM """+table+""" WHERE md5 NOT LIKE "" GROUP BY md5 HAVING count(md5)>1) OR sha1 IN (SELECT sha1 FROM """+table+""" WHERE sha1 NOT LIKE "" GROUP BY sha1 HAVING count(sha1)>1) OR sha256 IN (SELECT sha256 FROM """+table+""" WHERE sha256 NOT LIKE "" GROUP BY sha256 HAVING count(sha256)>1) ORDER BY md5, sha1, sha256;""")
					try:
						c.execute(selectRepeatedQuery)
					except Exception as e:
						raise e
					try:
						with open(outfilename+".csv","a",encoding="iso-8859-1") as file:
							for line in c.fetchall():
								print(line[5])
								res = line[0]+","+line[1]+","+line[2]+","+line[3]+","+line[4]+","+line[5]+";\n"
								file.write(res) 
							file.close()
						print("[INFO] Los datos fueron correctamente exportados al fichero %s.csv" %outfilename)
					except Exception as e:
						raise e
					finally:
						return
			elif exportType ==3:
				if not selectedTable:
					print("[!] No ha seleccionado ninguna tabla.")
					selected = selectTable()
					if not selected:
						return
				selectRepeatedQuery =("""SELECT id AS id,filename AS filename, filepath AS filepath,scanDate AS scanDate, md5 AS md5, sha1 AS sha1, sha256 AS sha256 FROM """+selectedTable+""" WHERE md5 IN (SELECT md5 FROM """+selectedTable+""" WHERE md5 NOT LIKE "" GROUP BY md5 HAVING count(md5)>1) OR sha1 IN (SELECT sha1 FROM """+selectedTable+""" WHERE sha1 NOT LIKE "" GROUP BY sha1 HAVING count(sha1)>1) OR sha256 IN (SELECT sha256 FROM """+selectedTable+""" WHERE sha256 NOT LIKE "" GROUP BY sha256 HAVING count(sha256)>1) ORDER BY md5, sha1, sha256;
				""")
				try:
					c.execute(selectRepeatedQuery)
				except Exception as e:
					raise e
				try:
					with open(outfilename+".csv","w",encoding="iso-8859-1") as file:
						file.write("ID,Ruta,Nombre,Fecha,MD5,SHA1,SHA256;\n")
						for line in c.fetchall():
							print(line[5])
							res = line[0]+","+line[1]+","+line[2]+","+line[3]+","+line[4]+","+line[5]+";\n"
							file.write(res) 
						file.close()
					print("[INFO] Los datos fueron correctamente exportados al fichero %s.csv" %outfilename)
				except Exception as e:
					raise e
				finally:
					return

			c.close()
			connection.close()

	elif exportType=="q" or exportType=="quit":
		return
	else:
		print("[!] Debe indicar una opción válida")
		exportResults()
		return

#Elimina los hashes de los ficheros repetidos que ya no existen 
def deleteHashes():
	if not selectedTable:
		print("[!] No ha seleccionado ninguna tabla.")
		selected = selectTable()
		if not selected:
			return
	selectRepeatedQuery =("""SELECT filepath AS filepath FROM """+selectedTable+""" WHERE md5 IN (SELECT md5 FROM """+selectedTable+""" WHERE md5 NOT LIKE "" GROUP BY md5 HAVING count(md5)>1) OR sha1 IN (SELECT sha1 FROM """+selectedTable+""" WHERE sha1 NOT LIKE "" GROUP BY sha1 HAVING count(sha1)>1) OR sha256 IN (SELECT sha256 FROM """+selectedTable+""" WHERE sha256 NOT LIKE "" GROUP BY sha256 HAVING count(sha256)>1) ORDER BY md5, sha1, sha256;
	""")
	try:

		connection = sqlite3.connect("HashDB.db")
		c = connection.cursor()
		c.execute(selectRepeatedQuery)
		rows = c.fetchall()
		print (rows)
	except Exception as e:
		raise e
	else:
		deleteRowQuery="""DELETE FROM """+selectedTable+""" WHERE filepath=?"""
		count=0
		for row in rows:
			print(row[0])
			print(os.path.exists(row[0]))
			if not os.path.exists(row[0]):
				print("Deleted")
				try:
					c.execute(deleteRowQuery,(row[0],))
				except Exception as e:
					raise e
				else:
					count +=1
		print("Eliminados correctamente %d registros"  %count)
	finally:
		connection.commit()
		c.close()
		connection.close()
		return

#Cambia la configuración por defecto de la aplicación
def changeConfiguration():
	print("\nIndique la opción que desea modificar en el formato \"OPCIÓN VALOR\"")
	for option in config:
		print(option,"\t",config[option])
	newValue = input("» ")
	if newValue =="q":
		return
	if not re.search(r'[^0-9A-Za-z\-\_\ ]',newValue):
		try:
			option,value = newValue.split(" ",1)
			updateOptionQuery="""UPDATE setup SET value=? WHERE option =?;"""
			connection = sqlite3.connect("HashDB.db")
			c = connection.cursor()
			c.execute(updateOptionQuery,(value,option))
			connection.commit()
		except Exception as e:
			#raise e
			print("[!] No se ha encontrado la opción deseada")
		else:
			getConfig()
		finally:
			return
	else:
		print("[!] No se ha encontrado la opción deseada")
		return

#Devuelve la configuración actual almacenada
def getConfig():
	getConfigQuery="""SELECT * FROM setup"""
	try:
		connection = sqlite3.connect("HashDB.db")
		c = connection.cursor()
		c.execute(getConfigQuery)
		global config
		for row in c.fetchall():
			config[row[0]] =row[1]

	except Exception as e:
		print(e)
	else:
		c.close()
		connection.close()	

#Main
if __name__ == "__main__":
	header()
	setup()
	time.sleep(1)
	print("[INFO] Sistema operativo %s detectado." %so)
	time.sleep(1)
	os.system(system[so]["clear"])
	while True:
		try:
			mainMenu()
			print("Pulse cualquier tecla para continuar.")
			input("» ")
			os.system(system[so]["clear"])
		except KeyboardInterrupt:
			sys.exit(0)