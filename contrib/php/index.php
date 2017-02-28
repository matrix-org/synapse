<?php
	/*
		__ Important !! __

		Do not forget to change values:
		  * $SharedSecret (at the bottom)
		  * $server_location (determains where to register the new user)
		  * db settings in query()

		and $redirect_path if you don't want the user to get redirected to /
	*/

	// PostgreSQL query class.
	/*
		Usage (two examples):

			$rows = new query("SELECT * FROM invites;");
			if ($rows) {
				foreach ($rows->get() as $row) {
					print_r($row);
				}
			}

			------

			$q = new query("INSERT INTO invites (owner, key) VALUES("@user:domain.com", "<super long sha246 hash>");
			$q->execute();

	*/
	class query {
		public $q;
		public $result;
		private $conHandle = null;
		private $dbhost = '127.0.0.1';
		private $dbuser = 'synapse';
		private $dbpass = '<SomeRandomPassword>';
		private $dbname = 'synapse';

		public function __construct($q) {
			$this->q = $q;
			$this->connect();
		}

		public function error() {
			return pg_last_error($this->conHandle);
		}

		private function connect() {
			// CREATE DATABASE dhsupport OWNER dhsupport
			// ALTER USER dhsupport WITH PASSWORD 'passwd';
			$this->conHandle = pg_connect("host=" . $this->dbhost . " user=" . $this->dbuser . " password=" . $this->dbpass . " dbname=" . $this->dbname);
			if (!$this->conHandle) {
				error_log("Connect failed: %s\n", $this->conHandle->connect_error);
				//exit();
				return false;
			} else {
				pg_query($this->conHandle, "CREATE TABLE IF NOT EXISTS invites (id SERIAL PRIMARY KEY, key VARCHAR(128), owner VARCHAR(120), regged TIMESTAMP WITH TIME ZONE default now(), used BOOL DEFAULT FALSE, UNIQUE(key));");
				return true;
			}
		}

		public function execute() {
			$this->result = pg_query($this->conHandle, $this->q);

			if (!$this->result) {
				error_log($this->q);
				die("Error: %s\n" . $this->conHandle->error);
				$this->close();
			}
			$this->close();
		}

		public function get() {
			$this->result = pg_query($this->conHandle, $this->q);

			if ($this->result && $this->result !== TRUE) {
				while ($row = pg_fetch_assoc($this->result))
					yield $row;
			}
			$this->close();
		}

		public function close() {
			//if($this->result)
			//      $this->result->free();
			pg_close($this->conHandle);
		}
	}

	function validate_input($obj) {
		$valid_chars = "/[^A-Za-z0-9\!\#\$\-\.\_]/";

		foreach($obj as $key => $val) {
			if (preg_match($valid_chars, $key) || preg_match($valid_chars, $val)) {
				header('Location: '. $redirect_path);
				die();
			}
		}
	}

	$redirect_path = '/';

	// TODO:
	// Super daft way of checking user input, but works for testing purposes.
	validate_input($_GET);
	validate_input($_POST);

	// If no key was supplied, redirect the user.
	if(!isset($_GET['K'])) {
		header('Location: '. $redirect_path);
		die();
	}

	// Grab info about the key (if it hasn't been used, if it has, return empty)
	$dict = array();
	$dictRaw = new query("SELECT owner, key FROM invites WHERE key='" . $_GET['K'] . "' AND used=false;");
	if ($dictRaw) {
		// The reason for this nested loop is because it's a dynamic
		// loop to get results from any query sort of, so I'm lazy and re-using.
		foreach ($dictRaw->get() as $row) {
			foreach($row as $key => $val)
				$dict[$key] = $val;
		}
	}

	// If 'owner' wasn't returned from the query, the key was already used.
	// So we'll redirect the user.
	if (!isset($dict['owner'])) {
		header('Location: '. $redirect_path);
		die();
	} else {
		// If it on the other hand wasn't used, we'll set it as used now and
		// give the user a new one for the submit fields.
		$q = new query("UPDATE invites SET used=true WHERE key='".$_GET['K']."';");
		$q->execute();
	}

	/*
		If we've gotten this far, it means that hopefully the userinput isn't malicious.
		And the key supplied should be valid, so it's time to check if we've supplied
		a username/password combo.. If we haven't the key will be set as used and a new
		key is generated for the next session (the POST session).
	*/
	$OTK = $_GET['K'];

	if(!isset($_POST['username']) || !isset($_POST['password'])) {
		$newKey = hash('sha256', random_bytes(64));
		$q = new query("INSERT INTO invites (key, owner) VALUES('".$newKey."', '".$dict['owner']."');");
		$q->execute();
		?>
			<html>
				<head>
					<style type="text/css">
							body {
								background-color: #2d2d2d;
								overflow: hidden;
							}

							#content {
								position: absolute;
								width: 100%;
								height: 100%;
								overflow: hidden;
							}

							.logo {
								position: absolute;
								width: 200px;
								height: 200px;
								left: 50%;
								top: 50%;
								margin-left: -100px;
								margin-top: -150px;
								background-image: url('./logo.png');
							}

							.fields {
								position: absolute;
								left: 50%;
								top: 50%;
								width: 200px;
								margin-left: -100px;
								margin-top: 75px;
							}

							.fields input {
								width: 200px;
							}

							.fields input[type=submit] {
								background-color: #00d1b2;
								border-color: transparent;
								color: #fff;
							}

							.fields input {
								align-items: center;
								border-radius: 3px;
								display: inline-flex;
								font-size: 1rem;
								height: 2.285em;
								justify-content: flex-start;
								line-height: 1.5;
								padding-left: .75em;
								padding-right: .75em;
								background-color: #fff;
								border: 1px solid #dbdbdb;
								color: #363636;
								box-shadow: inset 0 1px 2px rgba(10,10,10,.1);
								width: 100%;
								margin-top: 2px;
							}
					</style>
				</head>
			<body>
				<div id="content">
					<div class="logo"></div>
					<div class="fields">
						<form method="POST" action="./?K=<?php print $newKey; ?>">
							<input type="text" name="username" placeholder="Username">
							<input type="password" name="password" placeholder="Password">
							<input type="submit" value="Register">
						</form>
					</div>
				</div>
			</body>
			</html>
		<?php
	} else {

		/*
			This section is for when a KEY was given and POST gave us username/password.
		*/

		// == General settings:
		$server_location = "https://homeserver.domain.com";
		$chat_location = "https://chat.domain.com"; // Front-end if any
		$SharedSecret = "</etc/synapse/homeserver.yalm (registration_shared_secret value)>";
		// --

		$user = $_POST['username'];
		$pass = $_POST['password'];

		// Lets generate all the fields that synapse/matrix needs,
		// they are a <user>\x00<pass>\x00<notadmin|admin> combo hmac:ed with the reg secret.
		$mac = hash_hmac('sha1', $user . "\0" . $pass . "\0" . "notadmin", $SharedSecret);

		// And then put into a json object (see $payload).
		// note that "admin" is a TRUE|FALSE statement here, and not "admin"|"notadmin" (just to be confusing)
		$data = array(
			"user" => $user,
			"password" => $pass,
			"mac" => $mac,
			"type" => "org.matrix.login.shared_secret",
			"admin" => false
		);

		$payload = json_encode($data);

		// http://php.net/manual/en/function.curl-setopt.php
		$curl = curl_init($server_location."/_matrix/client/api/v1/register");
		curl_setopt($curl, CURLOPT_POSTFIELDS, $payload );
		curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'Content-Length: ' . strlen($payload)));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true );

		// DEBUG: If you're using a self signed cert for the homeserver,
		// make sure to uncomment these two, curl is strict on it's certificate chain by default.
		//curl_setopt($curl, CURLOPT_SSL_VERIFYHOST,0);
		//curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,0);

		$result = curl_exec($curl);
		// TODO: error handling
		// For instance, was the result good or bad?
		// Perhaps print any errors(?):
		//   print curl_error($curl);
		curl_close($curl);

		header('Location: https://'. $chat_location);
		die();
	}
?>
