# AdvisoryEmail
Send security advisory emails to system owners

Use the National Vulnerability Database's XML file holding active and recent CVEs and a list of assets to inform system owners of recent vulnerabilities.

2 Python Scripts are included here:
1. CveAdvisory.py: This script updates a local copy of the NVD, queries it to get latest CVEs and then emails the results in Excel format to previewers.
2. CveArchive.py: This script updates a local copy of the NVD, queries it to get CVEs from past years and then saves the results in Excel format.

Both scripts use vulnerabilities.py as a library and AdvisoryConfig.py as config data.