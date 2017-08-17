<?php
namespace Vuba\AuthN\Exception;

class LoginFailed extends AuthNException
{
    public function __construct($message){
        if ($message === null) {$msg = "Login failed";}
        else {$msg = $message;}
        parent::__construct($msg, RetCode::LOGIN_FAILED);
    }
}