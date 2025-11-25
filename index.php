<?php
// Coloque no início do seu script PHP
require_once 'TrafficSecurityManager.php';
$security = new TrafficSecurityManager();
$security->processSecurityCheck(); // Bloqueia automaticamente se quality = low
