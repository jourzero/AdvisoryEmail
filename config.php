<?php
// DB parameters
$dbName         = "cvedb";
$dbUser         = "cveadm";
$dbPwd          = "dbP4sswd!";
$dbHost         = "localhost";
$dbMainTable    = "cve";
$dbArchiveTable = "cve_archive";

// App config
$maxRows        = 200;
$minCvssScore   = 1.0;
$cveUriBase     = "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=";
$cweUriBase     = "https://cwe.mitre.org/data/definitions/";
$maxColLength   = 600;
?>
