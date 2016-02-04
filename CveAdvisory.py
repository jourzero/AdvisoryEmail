#! /usr/bin/python
#==================================================================
# CveAdvisory.py: This script updates a local copy of the NVD,
#                 queries it to get latest CVEs and then emails
#                 the results in Excel format to previewers.
#
#                 Add this script to a crontab job and run it
#                 every month. 
#==================================================================
import sys
import vulnerabilities as vul
import time
#from datetime import date
import datetime
import AdvisoryConfig as cfg
       
def main(argv):
    
    # Get report timelines  
    today           = datetime.date.today()
    endDate         = today.isoformat()
    startDate       = (today - datetime.timedelta(days=cfg.ReportPeriod)).isoformat()
    reportYear      = endDate.split('-')[0]
    reportMonth     = endDate.split('-')[1]
    domain          = "YOURCOMPANY"

            
    #Get latest NVD data
    #print "- Getting the latest CVE data from the NVD site"
    #vul.getCveDataFromNVD(cfg.nvdCveXmlFile)

    # Process XML file
    print "- Processing XML file"
    nvdVulns = vul.processNvdXML(cfg.nvdCveXmlFile)
    
    # Update the local mysql database    
    print "- Updating local CVE database"
    vul.updateLocalCveDB(nvdVulns, cfg.dbMainTable)
    
    # Create CVEs-per-platform report in Excel
    print "- Getting per-platform CVE list from %s to %s" % (startDate, endDate)
    assetList = cfg.assetList
    advisories = vul.getCVEsByAsset(assetList, startDate, endDate)
    reportFile1=reportYear + "-" + reportMonth + " Vulnerability Alerts version 1.xlsx"
    print "- Saving the CVE-by-platform list to Excel as %s" % (reportFile1)
    vul.createCVEsByAssetReport(domain, advisories, reportYear, reportMonth, reportFile1)
    
    # Create cumulative CVE report in Excel (all CVEs created this year)
    reportFile2="%s-%s Yearly Cumulative CVEs.xlsx" %(reportYear, reportMonth)
    print "- Saving the cumulative CVE list to Excel as %s" % (reportFile2)
    vul.createSimpleCVEReport(reportYear, reportFile2, cfg.dbMainTable)
    
    print "- Emailing the advisory email with the Excel file attached"
    vul.emailReport(reportFile1, reportFile2)
    


if __name__ == "__main__":
    if len(sys.argv)!=1:
        print "\nThis script updates a local instance of the National Vulnerability Database (NVD) and queries it for CVEs released in the last %s days." %(cfg.ReportPeriod)
        print "Then, the results are saved to an Excel file and sent via email to previewers (for review prior to distribution)."
        print "\nUsage: This script takes no input variable."

    else:
        main(sys.argv)
