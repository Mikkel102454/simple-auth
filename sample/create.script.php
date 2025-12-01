<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	SimpleAuth::verify_password($_POST['password'],$_POST['password_confirm']);
	$cr_result = SimpleAuth::create_user($_POST['username'], false);

	$ha_result = SimpleAuth::confirm_hash($cr_result->user_id);

	// Don't use GET variables in production code.
	header('location:confirmation.php?confirmation='.urlencode($ha_result->confirmation));
}
catch(\Exception $e) {
    error_log($e->getTraceAsString());
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:create.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
