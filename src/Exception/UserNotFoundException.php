<?php
namespace Vuba\AuthN\Exception;

class UserNotFoundException extends AuthNException
{
    public function __construct(){
        parent::__construct("User not found", RetCode::USER_NOT_EXIST);
    }
}