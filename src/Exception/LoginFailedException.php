<?php
namespace Vuba\AuthN\Exception;

class LoginFailedException extends AuthNException
{
    public function __construct(){
        parent::__construct("Login failed", RetCode::LOGIN_FAILED);
    }
}