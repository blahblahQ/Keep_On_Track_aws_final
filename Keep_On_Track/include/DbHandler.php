<?php
 
/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 * No need for Delete functionality at API level
 */
class DbHandler {
 
    private $conn;

    function __construct() {
        require_once "DbConnect.php"; // dirname(__FILE__) . 
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }
 
    /* ------------- `users` table method ------------------ */
 
    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($name, $username, $email, $password, $policy) {
        require_once 'PassHash.php';
        $response = array();
 
        // First check if user already existed in db
        if (!$this->isUserExists($username)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);
 
            // Generating API key
            $api_key = $this->generateApiKey();
 
            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(name, username, email, password_hash, policy, api_key, status) values(?, ?, ?, ?, ?, ?, 1)");
            $stmt->bind_param("ssssss", $name, $username, $email, $password_hash, $policy, $api_key);
 
            $result = $stmt->execute();
 
            $stmt->close();
 
            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same username already existed in the db
            return USER_ALREADY_EXISTED;
        }
 
        return $response;
    }
 
    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     * 
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->bind_result($password_hash);
        $stmt->store_result();
 
        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password
 
            $stmt->fetch();
 
            $stmt->close();
 
            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();
 
            // user not existed with the email
            return FALSE;
        }
    }
 
    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($username) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, username, email, policy, api_key, status, created_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $api_key = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }
 
    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

 
    /**
     * Checking user email and returning password info
     * @param String $email 
     * @param String $password 
     * @return boolean User change password status success/fail
     * 
     */
    public function changePassword($email, $password) {

        require_once 'PassHash.php';

        // Generating new password hash
        $password_hash = PassHash::hash($password);

        // insert query
	    $stmt = $this->conn->prepare("UPDATE users u SET u.password_hash = ? WHERE u.email = ?");
        $stmt->bind_param("ss", $password_hash, $email);
 
        $result = $stmt->execute();
 
        $stmt->close();
 
        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return True;
        } else {
            // Failed to change user details
            return False;
        }

    }

    /* ------------- `journeys` table method ------------------ */
 
    /**
     * Creating new journey
     * @param String $user_id user id to whom journey belongs to
     */
    public function createJourney($user_id){//, $journey_name) {        
        $stmt = $this->conn->prepare("INSERT INTO journeys VALUES()");
        $result = $stmt->execute();
        $stmt->close();
 
        if ($result) {
            // journey row created
            // now assign the journey to user
            $new_journey_id = $this->conn->insert_id;
            $res = $this->createUserJourney($user_id, $new_journey_id);
            if ($res) {
                // journey created successfully
                return $new_journey_id;
            } else {
                // journey failed to create
                return NULL;
            }
        } else {
            // journey failed to create
            return NULL;
        }
    }
 
    /**
     * Fetching single Journey
     * @param String $journey_id id of the journey
     * j - journeys table
     * uj - user journeys table
     */
    public function getJourney($journey_id, $user_id) {
        if($user_id==1){
            // admin access
            // can see ALL journeys
            $stmt = $this->conn->prepare("SELECT j.id, j.journey_score, j.status, j.created_at FROM journeys j WHERE j.id = ?");
            $stmt->bind_param("i", $journey_id);
        }else{
            //normal user access
            // Can only view their own journeys
            $stmt = $this->conn->prepare("SELECT j.id, j.journey_score, j.status, j.created_at FROM journeys j, user_journeys uj WHERE j.id = ? AND uj.journey_id = j.id AND uj.user_id = ?");
            $stmt->bind_param("ii", $journey_id, $user_id);
        }
        
        if ($stmt->execute()) {
            $journey = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $journey;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching all user journeys
     * @param String $user_id id of the user
     * j - journeys table
     * uj - user journeys table
     */
    public function getAllUserJourneys($user_id) {
        $stmt = $this->conn->prepare("SELECT j.* FROM journeys j, user_journeys uj WHERE j.id = uj.journey_id AND uj.user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $journeys = $stmt->get_result();
        $stmt->close();
        return $journeys;
    }
    
        /**
     * Fetching all user journeys for admin to view
     * j - journeys table
     * uj - user journeys table
     */
    public function getAllUserJourneysAdmin() {
        $stmt = $this->conn->prepare("SELECT j.* FROM journeys j");
        $stmt->execute();
        $journeys = $stmt->get_result();
        $stmt->close();
        return $journeys;
    }
 
    /**
     * Updating Journey complete status 
     * @param String $journey_id id of the journey
     * @param String $journey_score score int
     * @param String $status journey status
     * j - journeys table
     * uj - user journeys table
    */ 
    public function updateJourney($user_id, $journey_id, $status) {
        $stmt = $this->conn->prepare("UPDATE journeys j, user_journeys uj SET j.status = ? WHERE j.id = ? AND j.id = uj.journey_id AND uj.user_id = ?");
        $stmt->bind_param("iii", $status, $journey_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    
    /* ------------- `user_journeys` table method ------------------ */
 
    /**
     * Function to assign a journey to user
     * @param String $user_id id of the user
     * @param String $journey_id id of the journey
     */
    public function createUserJourney($user_id, $journey_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_journeys(user_id, journey_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $journey_id);
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }
 
    /* ------------- `journey_data` table method ------------------ */
    
    /**
     * Updating Journey data table
     * @param String $journey_id id of the journey
     * @param String $user_id id of the user
     * @param String $x_gps gps x coordinate
     * @param String $y_gps gps y coordinate
     * @param String $z_gps gps z coordinate
     * @param String $x_acl accelerometer x coordinate
     * @param String $y_acl accelerometer y coordinate
     * @param String $z_acl accelerometer z coordinate
     * @param String $timestamp time when data was sampled
     * @param String $sample_no the sample number of the journey
     * 
     * jd - journey data table
     * j - journeys table
     * uj - user journeys table
     */ 
    public function updateJourneyData($journey_id, $user_id, $x_gps, $y_gps, $x_acl, $y_acl, $z_acl, $timestamp, $sample_no) {
        $db = new DbHandler();
        $result = $db->getJourney($journey_id, $user_id);
        if($result == NULL){
            //journey doesnt belong to user or doesnt exist
            return 0;
        }
        else if($result["status"]==1){
            // cant add data information to a completed journey
            return 0;
        }
        
        // At last we can add the journey data!
        $stmt = $this->conn->prepare("INSERT INTO journey_data(journey_id, x_gps, y_gps, x_acl, y_acl, z_acl, time_stamp, sample_no) VALUES(?, ?, ?, ?, ?, ?, ?, ?)" ); 
        $stmt->bind_param("idddddsi", $journey_id, $x_gps, $y_gps, $x_acl, $y_acl, $z_acl, $timestamp, $sample_no);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
}
 
?>