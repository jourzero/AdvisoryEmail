<html>
    <head>
        <?php   $software = htmlspecialchars($_GET["software"]); ?>
        <title>CVEs for <?php echo $software; ?></title>
	<link href="tablesorter/docs/css/jq.css" rel="stylesheet">
	<script src="tablesorter/docs/js/jquery-1.2.6.min.js"></script>
	<link href="tablesorter/dist/css/theme.default.min.css" rel="stylesheet">
	<script src="tablesorter/dist/js/jquery.tablesorter.min.js"></script>
	<script src="tablesorter/dist/js/jquery.tablesorter.widgets.min.js"></script>
	<script>
	$(function(){
		$('table').tablesorter({
			widgets        : ['zebra', 'columns'],
			usNumberFormat : false,
			sortReset      : true,
			sortRestart    : true
		});
	});
	</script>        
    </head>
<body>
<?php
    include "config.php";
    $table = $dbArchiveTable;

    // Get Asset name
    $dbh = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPwd);    
    $query = "select * from $table WHERE affected_software LIKE ? AND cvss_score > $minCvssScore ORDER BY cve_id DESC LIMIT $maxRows";
    $stmt = $dbh->prepare($query);
    $var = "%$software%";
    //$var = "$software";
    $stmt->bindParam(1, $var, PDO::PARAM_STR, 80);
    $stmt->execute();
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Printing table headers'
    echo "<h1>CVEs matching $software</h1>";
    echo "<table class='tablesorter'>\n<thead>\n<tr>\n";

    for($i=0; $i<$stmt->columnCount(); $i++)
    {        
        $meta = $stmt->getColumnMeta($i); // 0 indexed so 0 would be first column
        $fieldName = $meta['name'];
        echo "<th>$fieldName</th>";
    }
    echo "</tr></thead>\n<tbody>\n";

    // Print table rows
    foreach ($result as $row){
        echo "<tr>";
        $rowNum = 0;
        foreach($row as $cell){
            $cell = substr($cell, 0, $maxColLength);
            if ($rowNum == 0){
                $cell = "<a href='" . $cveUriBase . $cell . "' target='cveWin'>$cell</a>";
            }
            if ($rowNum == 13){
                $cweId = str_replace("CWE-", "", $cell);
                $cell = "<a href='" . $cweUriBase . $cweId . ".html' target='cweWin'>$cell</a>";
            }
            echo "<td>$cell</td>";
            $rowNum++;
        }
        echo "</tr>\n";
    }
    echo "</tbody>\n</table>\n";
    
//    echo "<pre>";
//    var_dump($result);
//    echo "</pre>";
    
?>
</body>
</html>