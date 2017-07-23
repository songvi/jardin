<?php

namespace Vuba\AuthN\AuthStack;

class AuthLdap extends AbstractAuth
{

    public function __construct(){
        $this->authSourceName = 'ldap';
    }
}
