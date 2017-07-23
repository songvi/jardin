<?php

namespace Vuba\AuthN\AuthStack;

class AuthStack extends AbstractAuth
{
    protected $authstack = array();

    /**
     * @param AbstractAuth $auth
     * @param $order
     */
    public function __construct(AbstractAuth $auth, $order = 100)
    {
        if(isset($this->authstack[$order])){
            $this->authstack[++$order] = $auth;
        }
        $this->authstack[$order] = $auth;
    }


    /**
     *
     */
    protected function sort()
    {
        ksort($this->authstack);
    }

    /**
     * @param AbstractAuth $auth
     * @param $order
     */
    public function addAuth(AbstractAuth $auth, $order = null)
    {
        $maxIndex = $this->getMaxOrder();
        if(isNull($order) || isset($this->authstack[$order])){
            $this->authstack[$maxIndex] = $auth;
        }
        else {
            $this->authstack[$order] = $auth;
        }
    }

    /**
     * @return AbstractAuth
     */
    public function getDefaultAuth(){
        foreach($this->authstack as $auth){
            if($auth instanceof AbstractAuth) return $auth;
        }
    }

    /**
     * @param $id
     * @param $passphrase
     * @return bool
     */
    public function login($id, $passphrase){

        $this->sort();

        foreach ($this->authstack as $auth)
        {
            if($auth instanceof AbstractAuth){
                if($auth->login($id, $passphrase)) return true;
            }
        }

        return false;
    }

    public function getMaxOrder(){
        $max = 0;
        foreach($this->authstack as $key => $value){
            if ($max < $key ) $max = $key;
        }
        return $max;
    }

    public function register($uid, $authSource = null){

    }

    public function userExiste($uid){
        $this->getDefaultAuth()->isExist($uid);
    }

    /**
     * @param $uid
     * @param $passphrase
     * @return bool
     */
    public function createUser($uid, $passphrase)
    {
        $this->getDefaultAuth()->createUser($uid, $passphrase);
    }
}
