# Email parameters
orig		= "noreply@yourdomain.com"
dest		= "email1@yourdomain.com,email2@yourdomain.com"
mx		= "mx.yourdomain.com"

# Reporting parameters
ReportPeriod 	= 60 #days
tbd             = "(TBD)"

# Asset Inventory
assetList   = ["AIX", "Adobe", "AirDefense", "Apache", "Aruba", "Avaya", "Blackberry", "Blue Coat", "Checkpoint", "Cisco", "Citrix", "Clam", "F5", "FileZilla", "Fortinet", "HP", "Java", "Jboss", "JunOS", "Juniper", "Lotus", "Microsoft", "MySQL", "Nagios", "Nokia", "OpenSSL", "OpenView", "Oracle", "Palo Alto", "Perl", "PureFTPd", "Red Hat", "Riverbed", "Ruby", "Solaris", "Symantec", "Tenable", "Tomcat", "Tuxedo", "Unicenter", "VMWare", "WebSphere", "Weblogic", "Websense"]

# Directory locations
incDir		= "include/"
repDir		= "reports/"
tmpDir		= "tmp/"

# Template file
excelTemplate    = "YYYY-MM Vulnerability Alerts version 1.xlsx"

# Resource names
#nvdCveXmlBase   = "http://static.nvd.nist.gov/feeds/xml/cve/"
nvdCveXmlBase   = "https://nvd.nist.gov/feeds/xml/cve/" 
nvdCveXmlFile 	= "nvdcve-2.0-2016.xml.zip"
nvdCveXmlFileBase = "nvdcve-2.0-"

# URL Bases for Mitre resources
cveUrlBase      = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
cweUrlBase      = "http://cwe.mitre.org/data/definitions/"

# NVD fields to use and their description
nvdFields   = ["CVE_ID","Date_Published","Last_Modified","Title","CVSS_Score","Severity","Affected_Software","Authentication_Required","Access_Complexity","Confidentiality_Impact","Integrity_Impact","Availability_Impact","Access_Vector","CWE_ID","External_References"]
nvdTypes    = ["CHAR(20) UNIQUE KEY","DATE","DATE","CHAR(255)","FLOAT","CHAR(15)","TEXT","CHAR(20)","CHAR(20)","CHAR(20)","CHAR(20)","CHAR(20)","CHAR(20)","CHAR(20)","TEXT"]
rptFields   = ["Year","Notice Month","Publish Date","CVE ID","Platform","Advisory Title","Last Modified","Advisory URL","CVSS Severity","Affected Software","References","Authentication Required","Access Complexity","Confidentiality Impact","Integrity Impact","Availability Impact","Access Vector","CVSS Score","CWE URL"]
rptFieldsYTD= ["Year","Notice Month","Publish Date","CVE ID","Advisory Title","Last Modified","Advisory URL","CVSS Severity","Affected Software","References","Authentication Required","Access Complexity","Confidentiality Impact","Integrity Impact","Availability Impact","Access Vector","CVSS Score","CWE URL"]
colComments = ["Search keyword in Affected S/W","Year the CVE was published","Month the CVE was published","Date the CVE was published","Common Vuln. & Exposure ID","Description for CVE","Date the CVE was last modified","URL where CVE details can be found","Severity from CVSS score: Low:=[<4.0], Med.:=[4.0-6.9], High:=[>=7.0]","Software affected by this vuln.","Ref. keywords defined at http://cve.mitre.org/data/refs/ ","(S):=Must authenticate once. (N):=No auth. needed. (M):=Requires 2+ auth. (w/ same or different cred.).", "(H):=Requires specialized access - priv. escal., social eng... (M):=Requires somewhat specialized access. (L):=Requires unspecialized access.", "(N):=No impact to Confid. (P):=No considerable disclosure. (C):=Total information disclosure.","II: (N):=No impact to integrity of system. (P):=Mod. of system files or data is possible. (C):=Total compromise of system integrity.","AI: (N):=No impact on the avail. of the system. (P):=Reduced perf. or interruptions in resource avail. (C):=Total unavail. of the affected resource.","AV: (L):=Vuln is exploitable only locally. (A):=Access is required from same subnet or segment. (N):=Remotely exploitable.","Score as per the Common Vulnerability Scoring System","URL for Common Weakness Enumeration"]
dbName      = "cvedb"
dbUser	    = "cveadm"
dbPwd       = "dbP4sswd!"
dbHost      = "localhost"
dbMainTable = "cve"
dbArchiveTable = "cve_archive"
