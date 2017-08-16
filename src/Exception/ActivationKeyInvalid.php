<?php
namespace Vuba\AuthN\Exception;

class ActivationKeyInvalid extends AuthNException
{
    public function __construct($message){
        parent::__construct($message, RetCode::ACTIVATION_KEY_INVALID);
    }
}