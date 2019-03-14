<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

use Zend\ServiceManager\AbstractPluginManager;
use Lcobucci\JWT\Builder;

class JwtBuilderPluginManager extends AbstractPluginManager
{
    protected $instanceOf = Builder::class;
}
