<?php
  //grab the JWT from provided source - cookie, session, or local storage
  //assume the secret to be the String 'secret'
	function validate_token($jwt, $secret = 'secret') {
		// split the jwt
		$tokenParts = explode('.', $jwt);
		$header = base64_decode($tokenParts[0]);
		$payload = base64_decode($tokenParts[1]);
		$signature_provided = $tokenParts[2];

		$present_timestamp = new DateTime();
		$present_timestamp = $present_timestamp->getTimestamp();
		//echo $present_timestamp."<br><br>";

		// check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
		$issued_at = json_decode($payload)->iat; //issued at
		$expiration = json_decode($payload)->exp; //expiration
		//echo $expiration."<br><br>";

		if ($present_timestamp > $expiration) {
			$is_token_expired = true;
		}
		else{
			$is_token_expired = false;
		}

		// build a signature based on the header and payload using the secret
		$base64_url_header = base64_encode($header);
		$base64_url_payload = base64_encode($payload);
		$signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
		$base64_url_signature = base64_encode($signature);

		// verify it matches the signature provided in the jwt
		$is_signature_valid = ($base64_url_signature === $signature_provided);

		//echo $payload.PHP_EOL;
		
		if ($is_token_expired) {
			echo 'JWT is invalid'; //it's invalid
		} else {
			echo json_decode($payload)->user_id; //it's valid - grab any relevant data for further verification
		}
	}

	validate_token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');

	
  //if JWT come in as Bearer <token>

  $jwt = explode(' ', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');

  $jwt = $jwt[1];

	$jwt = str_replace('"', '', $jwt);

	//echo $jwt;
