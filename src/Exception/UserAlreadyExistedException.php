<?php
namespace Vuba\AuthN\Exception;

class UserAlreadyExistedException extends AuthNException
{
    public function __construct(){
        parent::__construct("User already existed", RetCode::USER_ALREADY_EXISTED);
    }
}