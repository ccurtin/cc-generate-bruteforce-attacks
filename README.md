# Bruteforce Attack Reports

Author: Christopher James Curtin   <br />
Tags: Brute Force Report, Bruteforce, Brute-force, attacks, logs, apache, modsecurity   <br />
Requires at least: 3.5   <br />
Tested up to: 4.3   <br />
License: GNU General Public License v2 or later   <br />
License URI: http://www.gnu.org/licenses/gpl-2.0.html   <br />

See how many bots are hitting your wp-login.php page every month.

## Description

Bruteforce Attack Reports will extract gzipped archives on the fly(if necessary) and parse your access log files to see how many attacks are made to the wp-login.php page each month.

Uses regular expressions to find bot requests. example: https://regex101.com/r/zX7hU1/1

** Plugin requires knowledge of where access logs are stored RELATIVE to the Wordpress Plugins directory **

** update the constant 'RELATIVE_LOG_PATH';
default:

	define('RELATIVE_LOG_PATH' , '/../../../../logs');

## Installation

Install Bruteforce Attack Reports either via the WordPress.org plugin directory, or by uploading the files to your server.

On the admin dashboard menu, navigate to Settings > Generate Bruteforce Attack Reports and select a month to generate the report.

## Changelog
v0.0.1 alpha