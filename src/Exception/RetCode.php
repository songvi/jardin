<?php

namespace Vuba\AuthN\Exception;

class RetCode{
    const ACTION_NOT_ALLOWED    = 1001;
    const USER_NOT_EXIST        = 1002;
    const LOGIN_FAILED          = 1003;
    const ACTIVATION_KEY_INVALID    = 1004;
    const PASSWORD_NOT_MATCHED      = 1005;
    const PASSWORD_POLICY_ERROR     = 1006;
    const USER_ALREADY_EXISTED     = 1007;
}