<?php
/*
 * Plugin Name: Bruteforce Attack Reports
 * Description: Generates bruteforce attack reports
 * Version: 0.0.1
 * Plugin URI: https://christopherjamescurtin.com/
 * Author URI: https://christopherjamescurtin.com/
 * Author: Christopher James Curtin
 * Requires at least: 3.5
 * Tested up to: 4.3
 * Text Domain: cc-generate-bruteforce-attacks
 * Domain Path: /lang/
 * License: GNU General Public License v2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Tags: Brute Force Report, Bruteforce, Brute-force, attacks, logs, apache, mod_security
 * @package WordPress
 * @author Christopher James Curtin
 * @since 0.0.1
 */

/*
 TODO:
 	- create a DB for previous results and chart attacks on graph D3.js
 	
 	- for months that are previous to the current one... only extract once and save the $total 
 	  into the DB to call on page loads automatically of previously processed. 
 	  load results in simple HTML table
*/

// Deny access to file
if (!defined('ABSPATH')){
	exit;
}
/**
 * List, unzip, and parse monthly access log files. Use a regexes to display count requests to wp-login.php 40[3|4|6]
 * 
 * @author Christopher James Curtin <work@christopherjamescurtin.com>
 * @copyright 2015
 */

class Cc_Generate_Bruteforce_Attacks{
	// returns the current year
	private $currentYear;
	// returns the current month
	private $currentMonth;
	// array of "short" month names: Jun,Jul...
	private $searchMonth;
	// array of "full" month names: June,July...
	private $replaceMonth;
	private $getMonth;
	private $getYear;
	/**
	 * initalize properties and methods
	 * define the relative location of the logs folder
	 * @since 0.0.1
	 */
	public function __construct(){
		// optional; server should be already configured correctly by default
			// date_default_timezone_set('America/New_York');
		// relative path to log files (zipped or .log)
		define('RELATIVE_LOG_PATH','/../../../../logs');
		// $_GET dates
		$this->getMonth = esc_attr($_GET['month']);
		$this->getYear = esc_attr($_GET['year']);
		// current dates
		$this->currentYear = date("Y");
		$this->currentMonth = date("M");
		// print pretty
		$this->searchMonth  = array("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec");
		$this->replaceMonth = array("January","February","March","April","May","June","July","August","September","October","November","December");
		// activation
		register_activation_hook( __FILE__, array( $this, 'activation' ) );
		// adds the menu and settings page
		add_action('admin_menu', array($this, 'add_menu'));
		// runs immediately after admin_init. enough elements exist on screen to identify it	
		add_action('current_screen',array($this, 'admin_init'));

	}
	/**
	 * redirect to the plugin page after activation
	 * @since 0.0.1
	 */
	public function activation(){
 		wp_redirect(admin_url('options-general.php?page=cc_bruteforce_attack'));
	}
	/**
	 * increase our memory limit if on the plugins page to process large archives and then process logs
	 * @param object $screen 
	 * @link https://codex.wordpress.org/Class_Reference/WP_Screen
	 * @since 0.0.1
	 */
	public function admin_init($screen){
		if($screen->id === 'settings_page_cc_bruteforce_attack'){
			// Depending on your server, and log-file size you may need to adjust this.
			// Be aware not to exceed your limitations!
			ini_set('memory_limit', '1024M');
		}
		// starts processing selected log files via GET requests
		$this->process_logs();
	}
	/**
	 *  Add menu & page to WP dashboard to manage plugin reports  
	 *  @since 0.0.1
	 */
	public function add_menu() {
	    add_options_page(
	        'Generate Bruteforce Attack Report Settings', // page title 
	        'Generate Bruteforce Attack Report', // menu title
	        'manage_options', // capability
	        'cc_bruteforce_attack', // menu slug
	        array($this, 'settings_page') // menu callback
	    );
	}
	/**
	 * the add_menu() callback
	 * @since 0.0.1
	 */
	public function settings_page()
	{
		if(!current_user_can('manage_options')) {
			wp_die(__('You do not have sufficient permissions to access this page.'));
	    }
		$this->generate_log_list();
	}
	/**
	 * Lists all the available log archives
	 * @since 0.0.1
	 */
	public function generate_log_list() {
 		// navigate to log folder relatively;
		$logDir = __DIR__.'/../../../../logs';
		$logs  = opendir($logDir);
		while (false !== ($filename = readdir($logs))) {
			// if it contains .gz and if it isn't an FTP log, add to $files array
			if(stristr($filename, '.gz') !== FALSE && stristr($filename, 'ftp.') === FALSE){
		   		$files[] =  $filename;		
			}

		}
		// reverse sort order so that most recent months are at the top
		rsort($files);
		// explode the archive name at hyphens to create 3 parts per log file
		// remove .gz
		foreach($files as $fullLogName) {
			$ex = explode("-",str_replace('.gz','',$fullLogName), 3);
			$exploded_file_name[] = array($ex[0],$ex[1],$ex[2]);
		}
		/*
		 * 
		 * for each exploded filename, grab the [1] and [2] index 
		   which holds [month] and [year] of the archive respectively
		   to include in the links-list as $_GET values which will run process_logs()
		 *
		 * create labels replacing short month name with full month 
		 */
		foreach ($exploded_file_name as $key => $filename_parts) {
			$site = $filename_parts[0];
			// month the archive was created: Nov
			$month = $filename_parts[1];
			// month the archive was created: November
			$month_fullName = str_replace($this->searchMonth, $this->replaceMonth, $month);
			// year the current archive was created
			$year = $filename_parts[2];
			// pretty label to print, ex: November 20 2015
			$label = $month_fullName . " " . $filename_parts[2];
			// print out links that will process files via specified  $_GET request 
			echo '<a href="'.$_SERVER['REQUEST_URI'].'&sendFails=send&month='.$month.'&year='.$year.'">'.$label.'</a><br>';
			}
	}
	/**
	 * Check for valid $_GET request in headers and process logs.
	 * Grab log files, unzip(if necessary), read log by small increments
	 * @since 0.0.1
	 */
	public function process_logs(){
		// if $_GET variables aren't validated, don't continue.
		if(
			!isset($this->getMonth) || 
			!in_array($this->getMonth,$this->searchMonth) && 
			!isset($this->getYear) ||
			!in_array($this->getYear,range('2004', $this->currentYear))
		) {
			return;
		}
		$total_brute_attacks = '';
		// current directory + relative path to LOGS folder.
		$dl_path = __DIR__.RELATIVE_LOG_PATH; // parent folder of this script
		// grab the file we want results for
		$filename = $_SERVER["SERVER_NAME"].'-'.$this->getMonth.'-'.$this->getYear.'.gz';
		// keep things consistant across shared hosting environments
		$filename = str_replace('www.','',$filename);
		// entire path
		$file = $dl_path . DIRECTORY_SEPARATOR . $filename;
		// does the log exist?
		if(!is_file($file)){
		    header("{$_SERVER['SERVER_PROTOCOL']} 404 Not Found");
		    header("Status: 404 Not Found");
		    echo 'File not found!';
		    die;
		}
		// is the log readable?
		if(!is_readable($file)){
		    header("{$_SERVER['SERVER_PROTOCOL']} 403 Forbidden");
		    header("Status: 403 Forbidden");
		    echo 'File not accessible!';
		    die;
		}
		// used to append datetime to generated log files
		$dateTime = date('Y-m-d--hia', time());
		// Raising this value may increase performance
		$buffer_size = 4096*5; // read 20kb at a time
		// foreach log file
		foreach (new DirectoryIterator($dl_path) as $value) {
				// match log file
				preg_match("/($this->getMonth)(.*)($this->getYear)(.*-($this->getYear))(.*(log))/", $value , $matches);
				if(!$matches){
					continue;
				}
				else {
					// if a match is found, set the $log_file to parse
					$log_file_find = $_SERVER["SERVER_NAME"] . "-" . $matches[0];
					$log_file = $dl_path . DIRECTORY_SEPARATOR . $log_file_find;
				}
		}

		// if the month is not over yet, or if no log files exist for a given month, unzip and create them.
		if(
			$this->getMonth === $this->currentMonth && 
			$this->getYear === $this->currentYear || 
			!isset($log_file)
		) {
			// $file = the $_GET gzip. and convert to log. ex: 'localhost-Jul-2015.gz' > 'localhost-Jul-2015---2015-09-13--0838pm.log'
			$log_file = str_replace('.gz', '---' . $dateTime . '.log', $file);
			// if the log file doesn't already exit yet, extract its contents into a new log file so we can parse.
			if(!file_exists($log_file)){
				// Open our files (in binary mode)
				$file = gzopen($file, 'rb');
				$out_file = fopen($log_file, 'wb'); 
				// Keep repeating until the end of the input file
				// gzeof tests for EOF. While data exists..
				while(!gzeof($file)) {
					// Both fwrite and gzread and binary-safe
					fwrite($out_file, gzread($file, $buffer_size));
				}  
				// Files are done, close files
				fclose($out_file);
				gzclose($file);
			} 
		}
		// define the log file we're working with, and explode each line into an array
		$logFile = file_get_contents($log_file, true);
		$logFile =  explode("\n", $logFile);
		foreach ($logFile as $key => $log_newLine) {
				$string[] = $log_newLine;
		}
		// for each request (log line), match essentially: "POST //wp-login.php HTTP/1.0" 406
		// https://regex101.com/r/zX7hU1/1
		foreach ($string as $value) {
			preg_match_all("/(\"POST .*)(wp-login.php)([^\"]*\"\s)(\b40[6|3|4]\b)/", $value, $matches);
			// for every line that's a match add at to the total attacks array
			foreach ($matches[0] as $v) {
				$total_brute_attacks[] = $v;
			}
		}
		// format the number so it's easy to read
		$this->totes = number_format(count($total_brute_attacks));
		// fire off the notification
		add_action( 'admin_notices', array($this,'my_admin_error_notice') ); 
	}
	/**
	 * displays Bruteforce Attack results from parsed log file.
	 * @since 0.0.1
	 */
	function my_admin_error_notice() {
		$class = "brute-attacks";
		$message = "<strong style=\"color:red\">" . $this->totes . "</strong> Brute Force Attacks During " . $this->getMonth . " " . $this->getYear ;
	    echo "<div style=\"font-size:20px;padding:25px 25px 25px 0;\" class=\"$class\"> $message </div>"; 
	}
} // class wrapper

new Cc_Generate_Bruteforce_Attacks;

?>