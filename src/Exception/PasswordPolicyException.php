<?php

namespace Vuba\AuthN\Exception;

class PasswordPolicyException extends AuthNException
{
    public function __construct($message){
        if ($message === null) {$msg = "Password does not match with complexity policy";}
        else {$msg = $message;}
        parent::__construct($msg, RetCode::P);
    }
}