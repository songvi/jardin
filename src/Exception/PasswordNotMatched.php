<?php
namespace Vuba\AuthN\Exception;

class PasswordNotMatched extends AuthNException
{
    public function __construct($message = ""){
        parent::__construct("Password not matched", RetCode::PASSWORD_NOT_MATCHED);
    }
}