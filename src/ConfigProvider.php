<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

use Psr\Container\ContainerInterface;
use Lcobucci\JWT\Builder;
use Zend\ServiceManager\AbstractFactory\ConfigAbstractFactory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer;
use Phly\Expressive\ConfigFactory as ExpressiveConfigFactory;
use Zend\Expressive\Application;

class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => $this->getDependencies(),
            ConfigAbstractFactory::class => $this->getAbstractFactoryConfig(),
        ];
    }

    public function getDependencies() : array
    {
        return [
            'invokables' => [
                Parser::class                                       => Parser::class,
                ValidationData::class                               => ValidationData::class,
                LoginValidator::class                               => LoginValidator::class,
                RoleCalculator\DefaultRoleCalculator::class         => RoleCalculator\DefaultRoleCalculator::class,
            ],
            'abstract_factories' => [
            ],
            'aliases' => [
                RoleCalculator\RoleCalculator::class                => RoleCalculator\DefaultRoleCalculator::class,
            ],
            'factories' => [
                Authenticate::class                                 => ConfigAbstractFactory::class,
                Middleware\TokenEmitterHandler::class               => ConfigAbstractFactory::class,
                Middleware\BlacklistTokenOnWriteMiddleware::class   => ConfigAbstractFactory::class,
                Middleware\ValidateTokenMiddleware::class           => ConfigAbstractFactory::class,
                Middleware\LoginMiddleware::class                   => ConfigAbstractFactory::class,
                Middleware\RefreshTokenMiddleware::class            => ConfigAbstractFactory::class,
                Middleware\LogoutHandler::class                     => ConfigAbstractFactory::class,
                Middleware\RoleCalculatorMiddleware::class          => ConfigAbstractFactory::class,
                AuthProvider\JwtValidationProvider::class           => ConfigAbstractFactory::class,
                'config-jwt_params'                                 => ExpressiveConfigFactory::class,
                'config-security'                                   => ExpressiveConfigFactory::class,
                JwtBuilderPluginManager::class                      =>
                    function(ContainerInterface $container, $requestedName) {
                        return new JwtBuilderPluginManager($container, [
                            'invokables' => [
                                Builder::class => Builder::class,
                            ],
                        ]);
                    },
                Verify\Strategy\PluginManager::class                =>
                    function(ContainerInterface $container, $requestedName) {
                        return new Verify\Strategy\PluginManager($container, [
                            'factories' => [
                                Verify\Strategy\Email::class        => ConfigAbstractFactory::class,
                                Verify\Strategy\Sms::class          => ConfigAbstractFactory::class,
                            ]
                        ]);
                    }
            ]
        ];
    }

    public function getAbstractFactoryConfig()
    {
        return [
            Authenticate::class => [
                MemberAdapter\CanRetrieveMember::class,
                CanHashPassword::class,
                AuthStore\AuthStore::class,
            ],
            AuthProvider\JwtValidationProvider::class => [
                AuthStore\AuthStore::class,
                Parser::class,
                Signer::class,
                ValidationData::class,
                'config-jwt_params'
            ],
            Middleware\TokenEmitterHandler::class => [
                JwtBuilderPluginManager::class,
                Parser::class,
                Signer::class,
                ValidationData::class,
                'config-jwt_params'
            ],
            Middleware\LoginMiddleware::class => [
                Authenticate::class,
                LoginValidator::class,
            ],
            Middleware\RefreshTokenMiddleware::class => [
                Authenticate::class,
            ],
            Middleware\LogoutHandler::class => [
                Authenticate::class,
            ],
            Middleware\ValidateTokenMiddleware::class => [
                AuthProvider\JwtValidationProvider::class
            ],
            Middleware\BlacklistTokenOnWriteMiddleware::class => [
                Authenticate::class,
                'config-security'
            ],
            Middleware\RoleCalculatorMiddleware::class => [
                RoleCalculator\RoleCalculator::class,
                MemberAdapter\CanRetrieveMember::class
            ],
            Verify\Strategy\Email::class => [
                Verify\Sender\CanSendEmail::class
            ],
            Verify\Strategy\Sms::class => [
                Verify\Sender\CanSendSms::class
            ]
        ];
    }

    public function registerRoutes(Application $app, string $basePath = '/api/auth')
    {
        $app->route("$basePath/login", [
            Middleware\LoginMiddleware::class,
            Middleware\RoleCalculatorMiddleware::class,
            Middleware\TokenEmitterHandler::class,
        ], ['POST'], 'api.auth.login');

        $app->route("$basePath/refresh", [
            Middleware\RefreshTokenMiddleware::class,
            Middleware\TokenEmitterHandler::class,
        ], ['POST'], 'api.auth.refresh');

        $app->route("$basePath/logout", [
            Middleware\ValidateTokenMiddleware::class,
            Middleware\BlacklistTokenOnWriteMiddleware::class,
            Middleware\LogoutHandler::class,
        ], ['POST'], 'api.auth.logout');
    }
}
