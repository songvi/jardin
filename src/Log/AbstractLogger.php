<?php

namespace Vuba\AuthN\Log;
use Vuba\AuthN\Context\IContext;

/**
 * Describes a logger-aware instance
 */
class AbstractLogger implements LoggerInterface
{
    /**
     * System is unusable.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function emergency($message, IContext $context)
    {

    }

    /**
     * Action must be taken immediately.
     *
     * Example: Entire website down, database unavailable, etc. This should
     * trigger the SMS alerts and wake you up.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function alert($message, IContext $context)
    {

    }

    /**
     * Critical conditions.
     *
     * Example: Application component unavailable, unexpected exception.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function critical($message, IContext $context)
    {

    }

    /**
     * Runtime errors that do not require immediate action but should typically
     * be logged and monitored.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function error($message, IContext $context)
    {

    }

    /**
     * Exceptional occurrences that are not errors.
     *
     * Example: Use of deprecated APIs, poor use of an API, undesirable things
     * that are not necessarily wrong.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function warning($message, IContext $context)
    {

    }

    /**
     * Normal but significant events.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function notice($message, IContext $context)
    {

    }

    /**
     * Interesting events.
     *
     * Example: User logs in, SQL logs.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function info($message, IContext $context)
    {

    }

    /**
     * Detailed debug information.
     *
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function debug($message, IContext $context)
    {

    }

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed $level
     * @param string $message
     * @param IContext $context
     * @return null
     */
    public function log($level, $message, IContext $context)
    {

    }
}