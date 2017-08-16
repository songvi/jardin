<?php
namespace Vuba\AuthN\Exception;

class ActionNotAllowOnState extends AuthNException
{
    public function __construct($message){
        parent::__construct($message, RetCode::ACTION_NOT_ALLOWED);
    }
}