// Modified to use multi_query for bonus task 3.11.4
if ($conn->multi_query($sql)) {
    $return_arr = array();
    
    // Process all result sets
    do {
        if ($result = $conn->store_result()) {
            // Only fetch data from first result set (the SELECT)
            if (empty($return_arr)) {
                while($row = $result->fetch_assoc()){
                    array_push($return_arr,$row);
                }
            }
            $result->free();
        }
        // Check for errors
        if ($conn->errno) {
            echo "</div>";
            echo "</nav>";
            echo "<div class='container text-center'>";
            die('There was an error running the query [' . $conn->error . ']\n');
            echo "</div>";
        }
    } while ($conn->more_results() && $conn->next_result());
    
} else {
    echo "</div>";
    echo "</nav>";
    echo "<div class='container text-center'>";
    die('There was an error running the query [' . $conn->error . ']\n');
    echo "</div>";
}
