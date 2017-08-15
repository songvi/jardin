<?php

namespace Vuba\AuthN\Service;

interface IConfService{
    const MAX_REQUEST_REGISTER = 3;
    const ACTIVATION_CODE_LIFE_TIME = 16800;
    const MAX_REQUEST_FORGOTPW  = 3;
    const MAX_LOGIN_FAILED = 20;

    public function getUserStorage();
    public function getAuth();
}
