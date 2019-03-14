<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify\Strategy;

use Zend\ServiceManager\AbstractPluginManager;

class PluginManager extends AbstractPluginManager
{
    protected $instanceOf = CanVerify::class;
}
