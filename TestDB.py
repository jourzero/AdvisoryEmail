#!/usr/bin/python
#========================================================================
# TestDB.py: Test connection to DB
# Install mysqldb module on Debian as follows:
#		$ sudo apt-get install python-mysqldb
#========================================================================
import MySQLdb as mysql
import AdvisoryConfig as cfg
import getpass


# Get mysql root password
print "- Creating the database " + cfg.dbName
print "-- Enter password for the mysql cveadm user"
pw = getpass.getpass()

# Open database connection
print "-- Connecting to the mysql database "
db = mysql.connect(cfg.dbHost,"cveadm", pw, "cvedb")

# Prepare a cursor object using cursor() method
cur = db.cursor()

# Execute SQL query using execute() method.
print "-- Getting the mysql version "
cur.execute("SELECT VERSION()")
data = cur.fetchone()
print "Database version : %s " % data

# Create the database
print "-- Querying the database "
sql = "select count(*) from cve_archive" 
try:
    cur.execute(sql)
except Exception:
    print "NB: Database probably already exists."

data = cur.fetchone()
print "Count of rows in cve_archive: %s " % data
    
# Disconnect from DB server
print "-- Closing the connection"
db.close()


