# AdvisoryEmail
Send security advisory emails to system owners. Generate CVE report from software name.

Current Features:
* Download the National Vulnerability Database's XML files holding CVE details (current and past years)
* Import CVE data to MySQL
* Read a list of specific assets and inform system owners of recent vulnerabilities via emails
* Create an archive of all CVEs for the last few years
* Show a simple PHP report showing CVEs for a specific software (as per the CVE's "Affected Software" field)

Suggested Enhancements (maybe later):
* Add more setup information (DB, script tweaks, web report...)
* Better code (replace PHP, more comments, validations/encoding, auth/authz control to allow hosting)
* Save to Excel from web report