#!/usr/bin/python
#========================================================================
# CreateDB.py: Create a CVE database to be populated by NVD data
# Install mysqldb module on Debian as follows:
#		$ sudo apt-get install python-mysqldb
#========================================================================
import MySQLdb as mysql
import AdvisoryConfig as cfg
import getpass


# Get mysql root password
print "- Creating the database " + cfg.dbName
print "-- Enter password for the mysql root user"
pw = getpass.getpass()

# Open database connection
print "-- Connecting to the mysql database "
db = mysql.connect(cfg.dbHost,"root", pw, "mysql")

# Prepare a cursor object using cursor() method
cur = db.cursor()

# Execute SQL query using execute() method.
print "-- Getting the mysql version "
cur.execute("SELECT VERSION()")
data = cur.fetchone()
print "Database version : %s " % data

# Create the database
print "-- Creating the database "
sql = "CREATE DATABASE %s" %(cfg.dbName)
try:
    cur.execute(sql)
except Exception:
    print "NB: Database probably already exists."
    
# Disconnect from DB server
print "-- Closing the connection"
db.close()

# Open database connection
print "-- Connecting to the new database " + cfg.dbName
db = mysql.connect(cfg.dbHost,"root", pw, cfg.dbName)
cur = db.cursor()

# Drop main table if it already exist using execute() method.
print "-- Dropping the main table if it exists, to start fresh"
cur.execute("DROP TABLE IF EXISTS " + cfg.dbMainTable)

# Create main table
print "- Creating the main table " + cfg.dbMainTable
fieldSql=""
for i in xrange(0,len(cfg.nvdFields)):
    if fieldSql != "":
	fieldSql += " ,"
    fieldSql += "%s %s" %(cfg.nvdFields[i], cfg.nvdTypes[i])

sql = "CREATE TABLE %s ( %s )" %(cfg.dbMainTable, fieldSql)
cur.execute(sql)

# Drop archive table if it already exist using execute() method.
print "-- Dropping the archive table if it exists, to start fresh"
cur.execute("DROP TABLE IF EXISTS " + cfg.dbArchiveTable)

# Create archive table
print "- Creating the archive table " + cfg.dbArchiveTable
fieldSql=""
for i in xrange(0,len(cfg.nvdFields)):
    if fieldSql != "":
	fieldSql += " ,"
    fieldSql += "%s %s" %(cfg.nvdFields[i], cfg.nvdTypes[i])

sql = "CREATE TABLE %s ( %s )" %(cfg.dbArchiveTable, fieldSql)
cur.execute(sql)

# Grant access to table
#access =  "SELECT,INSERT,UPDATE,DELETE"
access =  "ALL"
print "- Granting access to new mysql user " + cfg.dbUser
sql = "GRANT %s  ON %s.* TO %s IDENTIFIED BY '%s'" %(access, cfg.dbName, cfg.dbUser, cfg.dbPwd)
cur.execute(sql)
 
# Disconnect from DB server
db.close()


