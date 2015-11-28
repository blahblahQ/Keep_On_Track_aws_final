<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';

define('SERVER_EMAIL', "noreply@keepontrack.com");
define('ADMIN_EMAIL', "cian.rafferty@ucdconnect.ie");

require '.././libs/Slim/Slim.php';
\Slim\Slim::registerAutoloader();
 
$app = new \Slim\Slim();
 
// User id from db - Global Variable
$user_id = NULL;
$debug = 1;

/**
 * 
 * API FUNCTIONS
 * 
 */


/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }
 
    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

 
/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

 
/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);
 
    // setting response content type to json
    $app->contentType('application/json');
 
    echo json_encode($response);
}

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorisation' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();
 
    // Verifying Authorisation Header
    if (isset($headers['Authorisation'])) {
        $db = new DbHandler();
 
        // get the api key
        $api_key = $headers['Authorisation'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user = $db->getUserId($api_key);
            if ($user != NULL)
                $user_id = $user["id"];
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

    
/**
 * Adding functionality to email new users. todo
 */
function emailNewUser($email, $name, $username, $policy){
 
   
    // subject
    $subject = 'Welcome to Keep On Track!';

    // header info
    $headers = "From: " . SERVER_EMAIL . "\r\n";
    $headers .= "BCC: " . ADMIN_EMAIL . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=ISO-8859-1\r\n";
    
    // html code with tags
    $message = '<html><body>';
    // Welcome image
    $message .= '<img src="ec2-52-17-226-29.eu-west-1.compute.amazonaws.com/Keep_On_Track/images/welcome.png" alt="Welcome" />';

    $message .= "<p></p>";
    $message .= "<h1>Welcome $name to Keep On Track!</h1>";
    $message .= "<p></p>";
    $message .= "<p>If you see this email please put a tick beside the section marked";
    $message .= "with [received welmcome email]</p>";
    $message .= "<p></p>";
    $message .= "<p>All the best,</p>";
    $message .= "<p></p>";
    $message .= "<p></p>";
    $message .= "<p>Keep On Track Team</p>";
    $message .= "<p>Your details are below:</p>";

    $message .= '<table rules="all" style="border-color: #666;" cellpadding="10">';
    $message .= "<tr style='background: #eee;'><td><strong>Name:</strong> </td><td>" . $name . "</td></tr>";
    $message .= "<tr><td><strong>Username:</strong> </td><td>" . $username . "</td></tr>";
    $message .= "<tr><td><strong>Policy:</strong> </td><td>" . $policy . "</td></tr>";
    $message .= "</table>";
    $message .= "</body></html>";
	
						
    mail($email, $subject, $message, $headers);//) {  // email New User!
   
}

/**
 * Adding functionality to email users about a password change
 */

function emailUserProfileUpdate($email, $name, $username){
    

    // subject
    $subject = 'Cant get into Keep On Track?';

    // header info
    $headers = "From: " . SERVER_EMAIL . "\r\n";
    $headers .= "BCC: " . ADMIN_EMAIL . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=ISO-8859-1\r\n";

    // html code with tags
    $message = '<html><body>';

    // forgotten password image
    $message .= '<img src="ec2-52-17-226-29.eu-west-1.compute.amazonaws.com/Keep_On_Track/images/forgot_password.png" alt="Welcome" style="width: 50%; height: 50%"/>';

    $message .= "<p></p>";
    $message .= "<h1>Forgot Something?</h1>";
    $message .= "<p></p>";
    $message .= "<p>Your login details have been successfully updated!</p>";
    $message .= "<p></p>";
    $message .= "<p>If you get this email please mark a tick beside [password change email]</p>";
    $message .= "<p>All the best,</p>";
    $message .= "<p></p>";
    $message .= "<p></p>";
    $message .= "<p>Keep On Track Team</p>";
    $message .= "<p>Your details are below:</p>";

    $message .= '<table rules="all" style="border-color: #666;" cellpadding="10">';
    $message .= "<tr style='background: #eee;'><td><strong>Name:</strong> </td><td>" . $name . "</td></tr>";
    $message .= "<tr><td><strong>Username:</strong> </td><td>" . $username . "</td></tr>";
    $message .= "</table>";
    $message .= "</body></html>";
	
	// email user!				
    mail($email, $subject, $message, $headers);

}

//todo. add functionality to enable user to create a new password


 /**
 * ******************************************************************************************************
 * 					                        AUTHORISATION ENDPOINT
 * ******************************************************************************************************
 */
 
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'username', 'email', 'password', 'policy' ));
 
            $response = array();
 
            // reading post params
            $name = $app->request->post('name');
            $username = $app->request->post('username');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $policy = $app->request->post('policy');
 
            // validating email address
            validateEmail($email);
 
            $db = new DbHandler();
            $res = $db->createUser($name, $username, $email, $password, $policy);
 
            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
		        // email a welcome email to the new user
                emailNewUser($email, $name, $username, $policy);
                echoRespnse(201, $response);
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
                echoRespnse(200, $response);
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this username already exists";
                echoRespnse(200, $response);
            }
        });
 
/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
 
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);
 
                if ($user != NULL) {
                    $response["error"] = false;
                    $response['name'] = $user['name'];
                    $response['username'] = $user['username'];
                    $response['email'] = $user['email'];
                    $response['policy'] = $user['policy'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }
 
            echoRespnse(200, $response);
        });
 
/**
 * Changing password info
 * method get
 * params - email
 * url - /profile
 */
$app->post('/profile', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
	    $password = $app->request()->post('password');

            $response = array();

            $db = new DbHandler();
 
            // get the user by email
            $user = $db->getUserByEmail($email);
            // Does a user with this email exist?
            if ($user != NULL) {
		      // getting user details
                $name = $user['name'];
                $username = $user['username'];
		      // try to change the password
                if ($db->changePassword($email, $password)) {
                    $response["error"] = false;
                    $response['message'] = "User login details updated successfully!";
		            // email user about password update
                    emailUserProfileUpdate($email, $name, $username);
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                } 
		echoRespnse(201, $response);
            } else {
                // user password failed to update
                $response['error'] = true;
                $response['message'] = 'Password change failed. No Email account exists for this user';
				echoRespnse(400, $response);
            }
            
        });
	
/**
 * ******************************************************************************************************
 * 					                        API REQUESTS
 * ******************************************************************************************************
 */


	
/**
 * Creating new journey in db
 * method POST
 * url - /new_journey/
 * params - none
 */
$app->post('/journey', 'authenticate', function() use ($app) {
 
            $response = array();
            $journey = $app->request->post('journey');
 
            global $user_id;
            $db = new DbHandler();
            
            // Admin is user 1. Special privedges
            // but cant add journeys
            if($user_id == 1){
                $response["error"] = false;
                $response["message"] = "Admin can only view journeys";
                echoRespnse(400, $response);
                $app->stop();
            }
            // creating new journey
            $journey_id = $db->createJourney($user_id);//, $journey);
 
            if ($journey_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Journey created successfully";
                $response["journey_id"] = $journey_id;
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create journey. Please try again";
            }
            echoRespnse(201, $response);
        });        
        
/**
 * Listing all journeys of particual user
 * method GET
 * url /journey          
 */
$app->get('/journey', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // Admin is user 1. Special privedges
            // Can see all journeys
            if($user_id == 1){
                // admin fetching all user journeys
                $result = $db->getAllUserJourneysAdmin();
            }else{
                // fetching all users journeys
                $result = $db->getAllUserJourneys($user_id);
            }
            
            $response["error"] = false;
            $response["journey"] = array();
 
            // looping through result and preparing journeys array
            while ($journey = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $journey["id"];
                $tmp["journey_score"] = rand(1,100);//$journey["journey_score"];	// generating random score since analysis doesnt work
                $tmp["status"] = $journey["status"];
                $tmp["createdAt"] = $journey["created_at"];
                array_push($response["journey"], $tmp);
            }
 
            echoRespnse(200, $response);
        });
        
/**
 * Listing single journey of particular user
 * method GET
 * url /journey/:id
 * Will return 404 if the journey doesn't belongs to user
 */
$app->get('/journey/:id', 'authenticate', function($journey_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetch journey
            $result = $db->getJourney($journey_id, $user_id);
 
            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["journey_score"] =  rand(1,100);//$result["journey_score"];	// generating random score since analysis doesnt work
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Adding sample data points to Journeys data table
 * method PUT
 * url - //:id
 */
$app->post('/journey/:id', 'authenticate', function($journey_id) use($app) {
            // check for required params
            verifyRequiredParams(array('x_gps', 'y_gps', 'x_acl', 'y_acl', 'z_acl', 'timestamp', 'sample_no'));
            
            // reading post params
            $x_gps = $app->request->post('x_gps');
            $y_gps = $app->request->post('y_gps');
            $x_acl = $app->request->post('x_acl');
            $y_acl = $app->request->post('y_acl');
            $z_acl = $app->request->post('z_acl');
            $timestamp = $app->request->post('timestamp');
            $sample_no = $app->request->post('sample_no');
            $response = array();
            
            global $user_id;    
            // Admin is user 1. Special privedges                 
            // but cant post sample points
            if($user_id == 1){
                $response["error"] = false;
                $response["message"] = "Admin can only view journeys";
                echoRespnse(400, $response);
                $app->stop();
            }
            
            $db = new DbHandler();
            $response = array();
            
            // updating journey
            $result = $db->updateJourneyData($journey_id, $user_id, $x_gps, $y_gps, $x_acl, $y_acl, $z_acl, $timestamp, $sample_no);
            if ($result) {
                // Journey data passed successfully
                $response["error"] = false;
                $response["message"] = "Journey sample data successfully recieved";
		echoRespnse(200, $response);
            } else {
                // journey data failed upload
                $response["error"] = true;
                $response["message"] = "Journey sample data upload failed. Please try again!";
		echoRespnse(400, $response);
            }
            
        });        
        
/**
 * Updating Journey complete status
 * method PUT
 * params -
 * url - /journey/:id
 */
$app->put('/journey/:id', 'authenticate', function($journey_id) use($app) {
            // check for required params
            //verifyRequiredParams(array('status'));
 
            global $user_id;      
            
            // Admin is user 1. Special privedges          
            // but cant change journey status
            if($user_id == 1){
                $response["error"] = false;
                $response["message"] = "Admin can only view journeys";
                echoRespnse(400, $response);
                $app->stop();
            }
            
            $status = 1;//$app->request->put('status');
 
            $db = new DbHandler();
            $response = array();
 
            // updating journey
            $result = $db->updateJourney($user_id, $journey_id, $status);
            if ($result) {
                // journey updated successfully
                $response["error"] = false;
                $response["message"] = "Journey status updated successfully";
            } else {
                // journey failed to update
                $response["error"] = true;
                $response["message"] = "Journey status failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });
  
        
/*
 * 
 * TESTING CALLS
 * 
 */
          
        
/**
 * test function
 * url - /test
 * method - GET
 * 
 * todo: add some function to output values from the table for testing
 * todo: add password retrieval?
 * 
 */
$app->get('/test', function() {
        
	global $debug;
        $response = array();
	$debug = $debug + 1;
        
        //echo("...TEST\n");
        $response["error"] = false;
        $response["message"] = " TEST...";

        echoRespnse(200, $response);
});




// run the slim php framework. This processes and sends off the http responses.
$app->run();        
?>
