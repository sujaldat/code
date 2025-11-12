// Use prepared statement to prevent SQL injection
$stmt = $conn->prepare("SELECT id, name, eid, salary, birth, ssn, phoneNumber, address, email, nickname, Password 
                         FROM credential 
                         WHERE name=? AND Password=?");
$stmt->bind_param("ss", $input_uname, $hashed_pwd);
$stmt->execute();
$result = $stmt->get_result();

$return_arr = array();
if ($result) {
    while($row = $result->fetch_assoc()){
        array_push($return_arr,$row);
    }
}
$stmt->close();




$stmt = $conn->prepare("SELECT id, name, eid, salary, birth, ssn, password, nickname, email, address, phoneNumber 
                        FROM credential");
$stmt->execute();
$result = $stmt->get_result();

$return_arr = array();
if ($result) {
    while($row = $result->fetch_assoc()){
        array_push($return_arr,$row);
    }
}
$stmt->close();
