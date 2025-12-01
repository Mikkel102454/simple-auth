<?php
require_once('include.php');

try {
	if(!SimpleAuth::validate_tfa_code(SimpleAuth::user_id(), (string)$_POST['code'])){
		header('location:qr.php?qr='.urlencode($_POST['qr']));
		return;
	}
	header('location:.');
}
catch(\Exception $e) {
	Ufo::call('alert',SimpleAuth::error_string($e->getMessage()));
	Ufo::call('dialog_enable','<i class="fas fa-unlock"></i><span>Login</span>');
}
