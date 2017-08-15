<?php

namespace Vuba\AuthN\AuthStack;

class AuthLdap extends AbstractAuth
{
    public $conn;

    public function __construct($config)
    {

    }

    public function isReadOnly(){
        return true;
    }

    public function isExist($uid){
        return false;
    }

    public function countUser(){
        return 0;
    }

    public function login($uid, $passphrase){
        return $this->checkPassword($uid, $passphrase);
    }
    /**
     * @param $id
     * @param $passphrase
     * @return UserObject or false
     *
     */
    public function checkPassword($uid, $passphrase){
        return false;
    }

    public function listUser($state){
        return [];
    }
}
