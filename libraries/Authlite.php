<?php
/**
 * Authlite library
 * 
 * Based on Kohana's Auth library.
 *
 * @package		Layerful
 * @subpackage	Modules
 * @author		Layerful Team <http://layerful.org/>
 * @author		Fred Wu <fred@beyondcoding.com>
 * @copyright	BeyondCoding
 * @license		http://layerful.org/license MIT
 * @since		0.3.0
 */
class Authlite_Core {
	
	protected $session;
	protected $config_name;
	protected $config;
	protected $user_model;
	protected $username_column;
	protected $password_column;
	protected $session_column;

	/**
	 * Create an instance of Auth.
	 *
	 * @param string $config config file name
	 * @return object
	 */
	public static function factory($config_name = 'authlite')
	{
		return new Authlite($config_name);
	}

	/**
	 * Return a static instance of Auth.
	 *
	 * @return object
	 */
	public static function instance($config_name = 'authlite')
	{
		static $instance;

		// Load the Authlite instance
		empty($instance) and $instance = new Authlite($config_name);

		return $instance;
	}

	public function __construct($config_name = 'authlite')
	{
		$this->session = Session::instance();
		$this->config  = Kohana::config($config_name);
		$this->config_name = $config_name;
		
		$this->user_model      = $this->config['user_model'];
		$this->username_column = $this->config['username'];
		$this->password_column = $this->config['password'];
		$this->session_column  = $this->config['session'];
		
		Kohana::log('debug', 'Authlite Library loaded');
	}

	/**
	 * Check if there is an active session.
	 *
	 * @return object|false
	 */
	public function logged_in()
	{
		// Get the user from the session
		$user = $this->session->get($this->config['session_key']);
		
		$status = is_object($user) ? true : false;
		
		// Get the user from the cookie
		if ($status == false)
		{
			$token = cookie::get("authlite_{$this->config_name}_autologin");
			
			if (is_string($token))
			{
				$user = ORM::factory($this->user_model)->find(array($this->session_column => $token));
				
				if (is_string($user->username))
				{
					$status = true;
					$this->session->set($this->config['session_key'], $user);
				}
			}
		}

		if ($status == true)
		{
			return $user;
		}
		
		return false;
	}

	/**
	 * Returns the currently logged in user, or FALSE.
	 *
	 * @return object|false
	 */
	public function get_user()
	{
		if ($this->logged_in())
		{
			return $this->session->get($this->config['session_key']);
		}

		return false;
	}

	/**
	 * Attempt to log in a user by using an ORM object and plain-text password.
	 *
	 * @param string username to log in
	 * @param string password to check against
	 * @param boolean enable auto-login
	 * @return object|false
	 */
	public function login($username, $password, $remember = false)
	{
		if (empty($password))
		{
			return false;
		}
		
		$user = ORM::factory($this->user_model)->where($this->username_column, $username)->find();
		
		if ($user->{$this->password_column} === $this->hash($password))
		{
			$this->session->set($this->config['session_key'], $user);
			
			if ($remember == true)
			{
				$token = $this->session->id();
				$user->{$this->session_column} = $token;
				$user->save();
				cookie::set("authlite_{$this->config_name}_autologin", $token, $this->config['lifetime']);
			}
			
			return $user;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Log out a user by removing the related session variables.
	 *
	 * @param boolean $destroy completely destroy the session
	 * @return boolean
	 */
	public function logout($destroy = false)
	{
		if (cookie::get("authlite_{$this->config_name}_autologin"))
		{
			cookie::delete("authlite_{$this->config_name}_autologin");
		}
		
		if ($destroy === true)
		{
			// Destroy the session completely
			Session::instance()->destroy();
		}
		else
		{
			// Remove the user from the session
			$this->session->delete($this->config['session_key']);

			// Regenerate session_id
			$this->session->regenerate();
		}

		return ! $this->logged_in();
	}
	
	protected function hash($str)
	{
		return hash($this->config['hash_method'], $str);
	}

} // End Authlite