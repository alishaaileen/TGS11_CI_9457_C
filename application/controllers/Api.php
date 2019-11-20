<?php
	defined('BASEPATH') OR exit('No direct script access allowed');
	
    require APPPATH . 'third_party/REST_Controller.php';
	require APPPATH . 'third_party/Format.php';
	
	use Restserver\Libraries\REST_Controller;
	
    header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
	
    class Api extends REST_Controller {
        public function __construct() {
            parent::__construct();
            
            // Load these helper to create JWT tokens
            $this->load->helper(['jwt', 'authorization']); 
		}
		
		public function hello_get()
		{
			$tokenData = 'Hello World!';
			
			// Create a token
			$token = AUTHORIZATION::generateToken($tokenData);
			// Set HTTP status code
			$status = parent::HTTP_OK;
			// Prepare the response
			$response = ['status' => $status, 'token' => $token];
			// REST_Controller provide this method to send responses
			$this->response($response, $status);
		}

			public function login_post()
			{
				// Have dummy user details to check user credentials
				// send via postman
				$dummy_user = [
					'username' => 'Test',
					'password' => 'test'
				];
				// Extract user data from POST request
				$username = $this->post('username');
				$password = $this->post('password');
				// Check if valid user
				if ($username === $dummy_user['username'] && $password === $dummy_user['password']) {
					
					// Create a token from the user data and send it as reponse
					$token = AUTHORIZATION::generateToken(['username' => $dummy_user['username']]);
					// Prepare the response
					$status = parent::HTTP_OK;
					$response = ['status' => $status, 'token' => $token];
					$this->response($response, $status);
				}
				else {
					$this->response(['msg' => 'Invalid username or password!'], parent::HTTP_NOT_FOUND);
				}
			}
    }
    /* End of file Api.php */
