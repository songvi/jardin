<?php
namespace Vuba\AuthN\Exception;

class LoginFailed extends AuthNException
{
    public function __construct($message){
        parent::__construct($message, RetCode::LOGIN_FAILED);
    }
}