<?php defined('SYSPATH') or die('No direct script access.');

class Controller_User extends Controller
{
	public $authlite;
	
	public function before()
	{
		// Authlite instance
		$this->authlite = Authlite::instance();
		
		// login check
		if ( ! $this->authlite->logged_in() && Request::instance()->action != 'login') {
			
			$this->request->redirect('user/login');
			
		} else {
			
			// assigns the user object
			$this->user = $this->authlite->get_user();
			
			if ($this->authlite->logged_in() && Request::instance()->action == 'login') {
				$this->request->redirect('');
			}
		}
		
		parent::before();
	}
	
	public function action_login()
	{
		empty($_POST) or $this->authlite->login($_POST['username'], $_POST['password'], TRUE);
		
		if ($this->authlite->logged_in()) {
			$this->request->redirect('');
		} elseif ( ! empty($_POST)) {
			// login error message
		}
	}
	
	public function action_logout()
	{
		$this->authlite->logout();
		$this->request->redirect('');
	}
}