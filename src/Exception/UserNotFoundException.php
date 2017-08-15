<?php
namespace Vuba\AuthN\Exception;

class UserNotFountException extends AuthNException
{
    public function __construct($message){
        parent::__construct($message, RetCode::USER_NOT_EXIST);
    }
}