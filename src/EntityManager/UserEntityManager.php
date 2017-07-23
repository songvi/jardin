<?php

namespace Vuba\AuthN\EntityManager;

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";



class UserEntityManager
{
    protected  $em;
    public function __construc(){

        // Create a simple "default" Doctrine ORM configuration for Annotations
        $isDevMode = true;
        //$config = Setup::createAnnotationMetadataConfiguration(array(__DIR__."/src"), $isDevMode);
        // or if you prefer yaml or XML
        //$config = Setup::createXMLMetadataConfiguration(array(__DIR__."/config/xml"), $isDevMode);
        $config = Setup::createYAMLMetadataConfiguration(array(__DIR__."/yaml"), $isDevMode);

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
        $this->em = EntityManager::create($conn, $config);
    }

    public function loadUserFromDB($uid){
        if($this->em instanceof EntityManager){
            $user = $this->em->getRepository('authn')->find($uid);
        }
    }

    public function save(\Vuba\AuthN\User\UserObject $user){
        return false;
    }

    public function listUser(){
        return array();
    }

    /**
     * Search on uid, displayname, email address
     * @param array $criteria
     * @return array
     */
    public function search($criteria = array()){
        return [];
    }
}