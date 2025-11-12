<!DOCTYPE html>
<html>
<body>

<?php
session_start();

// Safely read inputs (avoid notices if keys missing)
$input_email      = isset($_GET['Email']) ? trim($_GET['Email']) : '';
$input_nickname   = isset($_GET['NickName']) ? trim($_GET['NickName']) : '';
$input_address    = isset($_GET['Address']) ? trim($_GET['Address']) : '';
$input_pwd        = isset($_GET['Password']) ? $_GET['Password'] : '';
$input_phonenumber= isset($_GET['PhoneNumber']) ? trim($_GET['PhoneNumber']) : '';

$eid = isset($_SESSION['eid']) ? $_SESSION['eid'] : null;
$uname = isset($_SESSION['name']) ? $_SESSION['name'] : null;
$id = isset($_SESSION['id']) ? intval($_SESSION['id']) : 0; // ensure integer ID

function getDB() {
    $dbhost="10.9.0.6";
    $dbuser="seed";
    $dbpass="dees";
    $dbname="sqllab_users";
    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error . "\n");
    }
    // set charset to avoid charset related injection issues
    $conn->set_charset('utf8mb4');
    return $conn;
}

$conn = getDB();

// Use prepared statements to remove SQL injection surface
if ($id > 0) {
    if ($input_pwd !== '') {
        // update including password
        $hashed_pwd = sha1($input_pwd);
        // update password in session
        $_SESSION['pwd'] = $hashed_pwd;

        $stmt = $conn->prepare(
            "UPDATE credential SET
                nickname = ?,
                email = ?,
                address = ?,
                PhoneNumber = ?,
                Password = ?
             WHERE ID = ?"
        );

        if ($stmt === false) {
            error_log("Prepare failed: " . $conn->error);
            $conn->close();
            header("Location: unsafe_home.php");
            exit();
        }

        // types: s=string, i=integer
        $stmt->bind_param(
            "sssssi",
            $input_nickname,
            $input_email,
            $input_address,
            $input_phonenumber,
            $hashed_pwd,
            $id
        );

    } else {
        // update without changing password
        $stmt = $conn->prepare(
            "UPDATE credential SET
                nickname = ?,
                email = ?,
                address = ?,
                PhoneNumber = ?
             WHERE ID = ?"
        );

        if ($stmt === false) {
            error_log("Prepare failed: " . $conn->error);
            $conn->close();
            header("Location: unsafe_home.php");
            exit();
        }

        $stmt->bind_param(
            "ssssi",
            $input_nickname,
            $input_email,
            $input_address,
            $input_phonenumber,
            $id
        );
    }

    // execute and close
    if ($stmt->execute() === false) {
        error_log("Execute failed: " . $stmt->error);
        // proceed to close and redirect regardless to avoid revealing DB errors to user
    }
    $stmt->close();
}

$conn->close();
header("Location: unsafe_home.php");
exit();
?>

</body>
</html>































function getDB() {
    $dbhost="10.9.0.6";
    $dbuser="seed";
    $dbpass="dees";
    $dbname="sqllab_users";
    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error . "\n");
    }
    // set charset to avoid charset related injection issues
    $conn->set_charset('utf8mb4');
    return $conn;
}

$conn = getDB();
// Using prepared statements to remove SQL injection  possibility
if ($id > 0) {
    if ($input_pwd !== '') {
        // update including password
        $hashed_pwd = sha1($input_pwd);
        // update password in session
        $_SESSION['pwd'] = $hashed_pwd;
        $stmt = $conn->prepare(
            "UPDATE credential SET nickname = ?, email = ?,address = ?,PhoneNumber = ?,Password = ?WHERE ID = ?");
        if ($stmt === false) {
            error_log("Prepared failed: " . $conn->error);
            $conn->close();
            header("Location: unsafe_home.php");
            exit();
        }
        // types: s=string and there are 5 of these, i=integer
        $stmt->bind_param(
            "sssssi",$input_nickname,$input_email,
            $input_address,$input_phonenumber,$hashed_pwd,$id);

    } else {
        // update without changing password since password change is not requested
        $stmt = $conn->prepare(
            "UPDATE credential SET nickname = ?,email = ?,address = ?,PhoneNumber = ? WHERE ID = ?");
        if ($stmt === false) {
            error_log("Prepared failed: " . $conn->error);
            $conn->close();
            header("Location: unsafe_home.php");
            exit();
        }

    $stmt->bind_param("ssssi",$input_nickname,$input_email,$input_address,$input_phonenumber,$id);}
    $stmt->execute();
    $stmt->close();
}

$conn->close();
header("Location: unsafe_home.php");
exit();
?>

</body>
</html>
