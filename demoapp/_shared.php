<?php
require '../wepay.php';
Wepay::useStaging('YOUR CLIENT ID', 'YOUR CLIENT SECRET');
header('Content-Type: text/html; charset=utf-8');
session_start();
