<?php
// bootstrap.php
require_once __DIR__.'/../vendor/autoload.php';

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

#require_once __DIR__."/../vendor/autoload.php";

// Create a simple "default" Doctrine ORM configuration for Annotations
$isDevMode = true;
//$config = Setup::createAnnotationMetadataConfiguration(array(__DIR__."/src"), $isDevMode);
// or if you prefer yaml or XML
//$config = Setup::createXMLMetadataConfiguration(array(__DIR__."/config/xml"), $isDevMode);
$config = Setup::createYAMLMetadataConfiguration(array(__DIR__."/../src/doctrine.mapping/"), $isDevMode);

// database configuration parameters
$conn = array(
    'driver' => 'mysqli',
    "host" => "127.0.0.1",
    "port" => "3306",
    "user" => "test",
    "password" => "test",
    "dbname" => "authn",
    "charset" => 'utf8'
);

// obtaining the entity manager
$em = EntityManager::create($conn, $config);

