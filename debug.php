$stmt = $conn->prepare("UPDATE credential SET 
                        nickname=?,
                        email=?,
                        address=?,
                        PhoneNumber=?,
                        Password=?
                        WHERE ID=?");
$stmt->bind_param("sssssi", $input_nickname, $input_email, $input_address, $input_phone, $hashed_pwd, $id);
$stmt->execute();
$stmt->close();
