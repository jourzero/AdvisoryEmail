#! /usr/bin/python
#==================================================================
# CveArchive.py: This script updates a local copy of the NVD,
#                queries it to get CVEs from past years and then 
#                saves the results in Excel format.
#==================================================================
import sys
import vulnerabilities as vul
import time
import datetime
import AdvisoryConfig as cfg
       
def main(argv):
    
    thisYear        = datetime.date.today().year
    yearlyVulns = []
    allVulns = []

    # Get CVE data from the previous 3 years
    #for year in range(thisYear-4, thisYear):
    #for year in range(thisYear-2, thisYear):
    for year in range(2014, 2017):
        print "*** Processing CVE data for " + str(year)

        # Get NVD data
        xmlfile = cfg.nvdCveXmlFileBase + str(year) + ".xml"
        #print "- Getting CVE data from the NVD site for year " + str(year)
        #vul.getCveDataFromNVD(xmlfile)
    
        # Process XML file
        print "- Processing XML file " + xmlfile
        yearlyVulns = vul.processNvdXML(xmlfile)
        allVulns.extend(yearlyVulns)
        
    # Update the local mysql database    
    print "- Updating local CVE database"
    vul.updateLocalCveDB(allVulns, cfg.dbArchiveTable)
    
    # Create cumulative CVE report in Excel (all CVEs created this year)
    reportFile="%s-%s CVE Archive.xlsx" %(str(thisYear-1), str(thisYear))
    print "- Saving the cumulative CVE list to Excel as %s" % (reportFile)
    vul.createSimpleCVEReport(str(thisYear-1) + " to " + str(thisYear), reportFile, cfg.dbArchiveTable)

if __name__ == "__main__":
    if len(sys.argv)!=1:
        print "\nThis script updates a local instance of the National Vulnerability Database (NVD) and queries it for CVEs released in the last %s days." %(cfg.ReportPeriod)
        print "Then, the results are saved to an Excel file and sent via email to previewers (for review prior to distribution)."
        print "\nUsage: This script takes no input variable."

    else:
        main(sys.argv)
