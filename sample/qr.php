<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

$body = design('2fa qr code');
$body->el('img', ['src'=>$_GET['qr']]);
$body->el('br');
$form = $body->el('form', ['method'=>'post','action'=>'qr.script.php']);
$form->el('input',[
	'required',
	'name' => 'code',
	'inputmode' => 'numeric',
	'pattern' => '[0-9]{6}',
	'maxlength' => '6',
]);
$form->el('input',[
	'name' => 'qr',
	'hidden' => true,
	'value'=>empty($_GET['qr']) ? '' : $_GET['qr']
]);

$form->el('button',['type'=>'submit'])->te('Færdigør');