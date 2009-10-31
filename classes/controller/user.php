<?php defined('SYSPATH') or die('No direct script access.');

class Controller_User extends Controller
{
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