<?php

namespace Vuba\AuthN\AuthStack;

use Defuse\Crypto\Key;
use Ramsey\Uuid\Uuid;

abstract class AbstractAuth
{
    public $authSourceName;
    public $config;

    public function __construct($authSourceName, $config)
    {
        $this->authSourceName = $authSourceName;
        $this->config = $config;
    }

    /**
     * @param $id
     * @param $passphrase
     * @return UserObject or false
     *
     */
    public function checkPassword($uid, $passphrase)
    {
        return false;
    }

    /**
     * @param $uid
     * @return bool
     */
    public function isExist($uid)
    {

        return false;
    }

    public function isReadOnly(){
        return true;
    }

    public function login($uid, $passphrase){
        return false;
    }

    public function listUser($state){
        return array();
    }
}
