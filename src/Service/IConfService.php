<?php

namespace Vuba\AuthN\Service;

interface IConfService{
    const MAX_REQUEST_REGISTER = 3;
    const ACTIVATION_CODE_LIFE_TIME = 16800;
    const MAX_REQUEST_FORGOTPW  = 3;
    const MAX_LOGIN_FAILED = 20;

    public function getSqlConnection();
    public function getLdapConnection();
    public function getUserStorageType();
    public function getUserStorage();
    public function getAuthType();

    /**
     * mysql | ldap
     * @return mixed
     */
    public function getAuthStorage();
}
