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
	
	/**
	 * Controller methods that bypass the login
	 *
	 * @var array
	 */
	protected $ignored_methods = array();
	
	/**
	 * Kohana session object
	 *
	 * @var object
	 */
	protected $session;
	
	/**
	 * Configuration instance name
	 *
	 * @var string
	 */
	protected $config_name;
	
	/**
	 * Kohana config object
	 *
	 * @var object
	 */
	protected $config;
	
	/**
	 * Configured user model
	 *
	 * @var string
	 */
	protected $user_model;
	
	/**
	 * Username column
	 *
	 * @var string
	 */
	protected $username_column;
	
	/**
	 * Password column
	 *
	 * @var string
	 */
	protected $password_column;
	
	/**
	 * Session column
	 *
	 * @var string
	 */
	protected $session_column;
	
	/**
	 * Create an instance of Authlite.
	 *
	 * @param string $config config file name
	 * @return object
	 */
	public static function factory($config_name = 'authlite')
	{
		return new Authlite($config_name);
	}

	/**
	 * Return a static instance of Authlite.
	 *
	 * @return object
	 */
	public static function instance($config_name = 'authlite')
	{
		static $instance;

		// Load the Authlite instance
		empty($instance[$config_name]) and $instance[$config_name] = new Authlite($config_name);

		return $instance[$config_name];
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
		
		$this->ignored_methods = $this->session->get('authlite_ignored_methods');
	}
	
	/**
	 * Adds the method to the ignore list
	 *
	 * @param string|array $method 
	 * @return void
	 */
	public function add_to_ignore($method)
	{
		$this->ignored_methods[$this->config_name] =
			isset($this->ignored_methods[$this->config_name])
				? $this->ignored_methods[$this->config_name]
				: array();
		
		$method = is_string($method) ? array($method) : $method;
		$method = array_combine(array_keys(array_flip($method)), $method);
		
		$this->ignored_methods[$this->config_name] = array_merge($this->ignored_methods[$this->config_name], $method);
		
		$this->session->set('authlite_ignored_methods', $this->ignored_methods);
	}
	
	/**
	 * Removes the method from the ignore list
	 *
	 * @param string|array $method
	 * @return void
	 */
	public function remove_from_ignore($method)
	{
		$method = is_string($method) ? array($method) : $method;
		
		$this->ignored_methods[$this->config_name] = array_diff($this->ignored_methods[$this->config_name], $method);
			
		$this->session->set('authlite_ignored_methods', $this->ignored_methods);
	}

	/**
	 * Check if there is an active session.
	 *
	 * @return object|false|null
	 */
	public function logged_in()
	{
		if (in_array(Router::$method, $this->ignored_methods[$this->config_name]))
		{
			return true;
		}
		
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
				
				if ($user->loaded)
				{
					$status = true;
					$this->session->set($this->config['session_key'], $user);
					cookie::set("authlite_{$this->config_name}_autologin", $token, $this->config['lifetime']);
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
	 * @see self::logged_in()
	 * @return object|false
	 */
	public function get_user()
	{
		return $this->logged_in();
	}

	/**
	 * Attempts to log in a user
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
			// Regenerate session_id
			$this->session->regenerate();
			
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
	 * Logs out a user by removing the related session variables.
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
			$this->session->destroy();
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
	
	/**
	 * Hashes a string using the configured hash method
	 *
	 * @param string $str 
	 * @return string
	 */
	public function hash($str)
	{
		return hash($this->config['hash_method'], $str);
	}

} // End Authlite