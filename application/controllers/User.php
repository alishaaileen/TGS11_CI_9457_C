<?php
	use Restserver\Libraries\REST_Controller;
	defined('BASEPATH') OR exit('No direct script access allowed');

	require APPPATH . 'libraries/REST_Controller.php';
	require APPPATH . 'libraries/Format.php';	


    class User extends REST_Controller {
        public function __construct() {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, OPTIONS, POST, DELETE');
            header('Access-Control-Allow-Headers: Content-Type, Content-Length, Accept-Encoding');

            parent::__construct();
            $this->load->model('UserModel');
			$this->load->library('form_validation');
			$this->load->helper(['jwt', 'authorization']);
        }
        
        public function index_get() {
			$data = $this->verify_request();

			// Send the return data as reponse
			$status = parent::HTTP_OK;

			$response = ['status' => $status, 'data' => $data];

			$this->response($response, $status);
            return $this->returnData($this->db->get('users')->result(), false);
        }

        public function index_post($id = null) {
            $validation = $this->form_validation;
            $rule = $this->UserModel->rules();

            if ($id == null) {
                array_push($rule, [
                    'field' => 'password',
                    'label' => 'password',
                    'rules' => 'required'
                ],
                [
                    'field' => 'email',
                    'label' => 'email',
                    'rules' => 'required|valid_email|is_unique[users.email]'    
                ]);
            } else {
                array_push($rule, [
                    'field' => 'email',
                    'label' => 'email',
                    'rules' => 'required|valid_email'
                ]);
            }

            $validation->set_rules($rule);

            if (!$validation->run()) 
                return $this->returnData($this->form_validation->error_array(), true);
            
            $user = new UserData();
            $user->name = $this->post('name');
            $user->password = $this->post('password');
            $user->email = $this->post('email');

            if ($id == null) 
                $response = $this->UserModel->store($user);
            else 
                $response = $this->UserModel->update($user, $id);

            return $this->returnData($response['msg'], $response['error']);
		}
		
        public function index_delete($id = null) {
            if ($id == null)
                return $this->returnData('Parameter ID Tidak Ditemukan', true);

            $response = $this->UserModel->destroy($id);
            return $this->returnData($response['msg'], $response['error']);
        }

        public function returnData($msg, $error) {
            $response['error'] = $error;
            $response['message'] = $msg;

            return $this->response($response);
		}
		
		private function verify_request()
		{
			// Get all the headers
			$headers = $this->input->request_headers();

			// Extract the token
			$token = $headers['Authorization'];

			// Use try-catch
			// JWT library throws exception if the token is not valid
			try {
				// Validate the token
				// Successfull validation will return the decoded user data else returns false
				$data = AUTHORIZATION::validateToken($token);
				if ($data === false) {
					$status = parent::HTTP_UNAUTHORIZED;
					$response = ['status' => $status, 'msg' => 'Unauthorized Access!'];
					$this->response($response, $status);

					exit();
				} else {
					return $data;
				}
			} catch (Exception $e) {
				// Token is invalid
				// Send the unathorized access message
				$status = parent::HTTP_UNAUTHORIZED;
				$response = ['status' => $status, 'msg' => 'Unauthorized Access! '];
				$this->response($response, $status);
			}
		}

		public function login_post()
 		{
			$email = $this->post('email');
			$password = $this->post('password');
			$data = $this->db->get_where('users',['email' => $email])->result_array();
			// Check if valid user
			if ($email === $data[0]['email'] && password_verify($password,  $data[0]['password'])) {
				
				// Create a token from the user data and send it as reponse
				$token = AUTHORIZATION::generateToken(['email' => $data[0]['email']]);
				// Prepare the response
				$status = parent::HTTP_OK;
				$response = ['status' => $status, 'token' => $token];
				$this->response($response, $status);
			}
			else {
				$this->response(['msg' => 'Invalid email or password!'], parent::HTTP_NOT_FOUND);
			}
		}
    }


    class UserData {
        public $name;
        public $password;
        public $email;
    }
