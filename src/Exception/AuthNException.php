<?php

namespace Vuba\AuthN\Exception;

class AuthNException extends \Exception
{
    public function __construct($message, $code){
        parent::__construct($message, $code);
    }
}
